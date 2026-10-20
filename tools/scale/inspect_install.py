"""Inspect a target interpreter; -S appends library paths without running hooks."""
import sys
STARTUP = sorted(sys.modules)

import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sysconfig
import zipfile


def main():
    libraries = list(dict.fromkeys([sysconfig.get_path("purelib"), sysconfig.get_path("platlib")]))
    if sys.flags.no_site:
        sys.path.extend(libraries)
    installed, owned, hooks = {}, {}, []
    for dist in importlib.metadata.distributions():
        owner = dist.metadata["Name"]
        installed[owner] = dist.version
        for file in dist.files or ():
            record = file.hash
            digest = base64.urlsafe_b64decode(record.value + "=" * (-len(record.value) % 4)).hex() if record is not None and record.mode == "sha256" else None
            owned[Path(dist.locate_file(file)).resolve()] = (owner, digest, str(file).replace("\\", "/"))
    pending, visited = [Path(p) for p in libraries + sys.path if p], set()
    while pending:
        directory = pending.pop().resolve()
        if directory in visited:
            continue
        visited.add(directory)
        if directory.is_file() and zipfile.is_zipfile(directory):
            with zipfile.ZipFile(directory) as archive:
                if any(name.lower() in ("sitecustomize.py", "usercustomize.py", "sitecustomize/__init__.py", "usercustomize/__init__.py") for name in archive.namelist()):
                    raise ValueError("unowned_archived_startup_code")
        if not directory.is_dir():
            continue
        for entry in sorted(directory.iterdir()):
            name = entry.name.lower()
            special = any(name == prefix or name.startswith(prefix + ".") and name.endswith((".py", ".pyc", ".pyd", ".so")) for prefix in ("sitecustomize", "usercustomize"))
            if not special and not name.endswith((".pth", ".start")):
                continue
            paths = sorted(p for p in entry.rglob("*") if p.is_file()) if entry.is_dir() else [entry]
            for path in paths:
                if "__pycache__" in path.parts:
                    continue
                raw = path.read_bytes()
                text = raw.decode("utf-8-sig") if path.suffix.lower() in (".py", ".pth", ".start") else ""
                executable = special or name.endswith(".start") and any(s.strip() and not s.lstrip().startswith("#") for s in text.splitlines()) or name.endswith(".pth") and any(s.startswith(("import ", "import\t")) for s in text.splitlines())
                owner, record, relative = owned.get(path.resolve(), (None, None, entry.name))
                hooks.append({"path": relative, "owner": owner, "record_sha256": record,
                              "sha256": hashlib.sha256(raw).hexdigest(), "class": "executable" if executable else "path_only", "text": text})
                if name.endswith(".pth") and not executable:
                    for line in text.splitlines():
                        line = line.rstrip()
                        if line and not line.startswith("#") and (directory / line).exists():
                            pending.append(directory / line)
    print(json.dumps({"installed": installed, "startup_modules": STARTUP, "hooks": sorted(hooks, key=lambda r: (r["path"], r["sha256"])),
                      "python": sys.version, "isolated": sys.flags.isolated, "no_site": sys.flags.no_site,
                      "purelib_form": Path(libraries[0]).name}))


if __name__ == "__main__":
    main()

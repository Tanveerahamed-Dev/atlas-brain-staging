"""Attest native Windows installations of a pinned product lock, not local installs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def normalized(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def validate(lock, project, installed, profile):
    if profile == "runtime":
        # The measured subject has a standard-library-only runtime closure.
        if project["project"]["dependencies"]:
            raise ValueError("runtime_dependency_closure_needs_resolution")
        expected = {}
    else:
        # This Windows-only subject has no optional groups; all registry entries
        # belong to the complete dev closure (including pytest's Windows colorama).
        expected = {normalized(p["name"]): p["version"] for p in lock["package"]
                    if "registry" in p.get("source", {})}
        for requirement in project["dependency-groups"]["dev"]:
            name, version = requirement.split("==")
            if expected.get(normalized(name)) != version:
                raise ValueError("declared_development_pin_mismatch")
    if installed != expected:
        raise ValueError("locked_install_mismatch:" + json.dumps({"expected": expected, "actual": installed}, sort_keys=True))
    return expected


INSPECT = """
import sys
startup = sorted(sys.modules)
import hashlib, importlib.metadata, json, pathlib, sysconfig
hooks = []
distributions = {}
for dist in importlib.metadata.distributions():
    distributions[dist.metadata['Name']] = dist.version
    for file in dist.files or ():
        name = file.name.lower()
        if name.endswith(('.pth', '.start')) or name.startswith(('sitecustomize.', 'usercustomize.')):
            path = pathlib.Path(dist.locate_file(file))
            hooks.append({'path': str(file).replace('\\\\', '/'), 'owner': dist.metadata['Name'],
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                          'text': path.read_text(encoding='utf-8-sig')})
print(json.dumps({'installed': distributions, 'startup_modules': startup, 'hooks': hooks,
                  'python': sys.version, 'isolated': sys.flags.isolated,
                  'purelib_form': pathlib.Path(sysconfig.get_path('purelib')).name}))
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--profile", choices=("runtime", "dev"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise ValueError("native_windows_required")
    from tools.scale.measure import shape
    runtime = args.subject / ".venv" / "Scripts" / "python.exe"
    observed = json.loads(subprocess.check_output([str(runtime), "-I", "-c", INSPECT], encoding="utf-8"))
    installed = {normalized(k): v for k, v in observed["installed"].items()}
    lock_path, project_path = args.subject / "uv.lock", args.subject / "pyproject.toml"
    expected = validate(tomllib.loads(lock_path.read_text(encoding="utf-8")),
                        tomllib.loads(project_path.read_text(encoding="utf-8")), installed, args.profile)
    observed.update({"schema": 1, "status": "pass", "profile": args.profile,
                     "runner": shape(), "expected": expected,
                     "subject_head": subprocess.check_output(["git", "-C", str(args.subject), "rev-parse", "HEAD"], encoding="ascii").strip(),
                     "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                     "project_sha256": hashlib.sha256(project_path.read_bytes()).hexdigest(),
                     "editable_install": "virtual project in authoritative lock; no editable install or project .pth",
                     "scope": "full currently declared product runtime/dev set; future dependency changes require requalification"})
    args.out.write_text(json.dumps(observed, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

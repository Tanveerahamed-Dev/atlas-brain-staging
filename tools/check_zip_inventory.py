"""Verify the pinned ZIP using source as data; never execute the consumer."""
import ast
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.fence import RUNTIME_API, import_bindings

USING = "atlas_brain/evidence/archives.py"
REVISION = "a5a2959dd27bd6326e6e907f9866984aa41d7449"
DIGEST = "2c882be101d184cdfde60fdcfbff866ff8c0a49e5bdb17c8e0e369d8ee77f897"


def tracked_probe(payload, bindings):
    tool = str(Path(__file__).with_name("fence.py").resolve())
    tracked = subprocess.check_output(["git", "ls-files", "-z", "atlas_brain"], encoding="utf-8").split("\0")
    sources = {p: Path(p).read_bytes() for p in tracked if p}
    sources[USING] = payload
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for path, raw in sources.items():
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
        (root / "pyproject.toml").write_bytes(Path("pyproject.toml").read_bytes())
        subprocess.run(["git", "init", "-q", directory], check=True)
        subprocess.run(["git", "-C", directory, "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=root, check=True)
        probe = root / "atlas_brain/zip_policy_probe.py"
        probe.write_text("from .evidence.archives import zip_members\nuse = zip_members\n", encoding="utf-8", newline="\n")
        subprocess.run(["git", "-C", directory, "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=root, check=True)
        refused = []
        for api in sorted(RUNTIME_API[USING]):
            imports = [(local, local + api[len(origin):]) for local, origin in bindings.items()
                       if isinstance(origin, str) and (api == origin or api.startswith(origin + "."))]
            if not imports:
                raise ValueError("no actual exported binding for ZIP capability probe")
            local, expression = imports[0]
            probe.write_text(f"from .evidence.archives import {local}\n{expression}\n", encoding="utf-8", newline="\n")
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            result = subprocess.run([sys.executable, tool], cwd=root, capture_output=True, text=True, check=False)
            if result.returncode != 1 or "scope fence: 1 refused" not in result.stdout:
                raise ValueError("actual tracked CLI accepted a ZIP capability outside its using path")
            refused.append(api)
    return {"actual_source_tree": "allowed", "public_declaration_import": "allowed", "reexports_refused": refused}


def main():
    payload = subprocess.check_output(["git", "show", f"{REVISION}:{USING}"])
    if hashlib.sha256(payload).hexdigest() != DIGEST:
        raise ValueError("ZIP using source digest mismatch")
    tree = ast.parse(payload.decode("utf-8"))
    bindings = import_bindings(tree, USING)[0]
    def qualified(node):
        if isinstance(node, ast.Name):
            return bindings.get(node.id, "")
        base = qualified(node.value) if isinstance(node, ast.Attribute) else ""
        return base + "." + node.attr if base else ""
    used = {api for node in ast.walk(tree) if (api := qualified(node)) in RUNTIME_API[USING]}
    if used != RUNTIME_API[USING]:
        raise ValueError("ZIP grant differs from actual using-source inventory")
    print(json.dumps({"path": USING, "source_head": REVISION, "source_sha256": DIGEST,
                      "used_apis": sorted(used), "tracked_probe": tracked_probe(payload, bindings),
                      "scope": "source admission only; consumer not executed, ZIP behavior not verified"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

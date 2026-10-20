"""Hosted preparation; never installs anything on the author host."""
import hashlib
import json
from pathlib import Path
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from spike.safety import census


def main():
    if sys.version_info[:3] not in ((3, 14, 8), (3, 15, 0)):
        raise RuntimeError("interpreter_pin")
    # Must be launched with -I -S before any engine process starts.
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError("prestart_census_flags")
    (ROOT / ".s0").mkdir(exist_ok=True)
    (ROOT / ".s0" / "prestart-census.json").write_text(json.dumps(census(), sort_keys=True) + "\n", encoding="ascii")
    if "--references-only" not in sys.argv:
        catalogue = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "spike").glob("*.py"))}
        (ROOT / "spike" / "CATALOGUE.json").write_text(json.dumps(catalogue, sort_keys=True) + "\n", encoding="ascii")
        paths = {"tools": "tools/__init__.py", "tools.scale": "tools/scale/__init__.py", "tools.scale.workload": "tools/scale/workload.py"}
        closure = {name: {"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()} for name, path in paths.items()}
        (ROOT / ".s0" / "import-closure.json").write_text(json.dumps(closure, sort_keys=True) + "\n", encoding="ascii")
    for no_site in (0, 1):
        flags = ["-I", "-X", "utf8=1", "-X", "warn_default_encoding", "-W", "error::EncodingWarning"] + (["-S"] if no_site else [])
        command = [sys.executable] + flags + [str(ROOT / "tools" / "scale" / "startup_reference.py")]
        first = subprocess.check_output(command)
        if first != subprocess.check_output(command):
            raise ValueError("unstable_clean_startup_reference")
        from spike.admission import stdlib_names, stdlib_roots
        reference = json.loads(first)
        reference["stdlib_names"] = sorted(stdlib_names(stdlib_roots()))
        environment = "venv" if sys.prefix != sys.base_prefix else "base"
        path = ROOT / ".s0" / f"startup-{sys.platform}-{'.'.join(str(i) for i in sys.version_info[:3])}-{environment}-{no_site}.json"
        path.write_text(json.dumps(reference, sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()

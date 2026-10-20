"""Hosted preparation; never installs anything on the author host."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from spike.safety import census


def main():
    if sys.version_info[:3] not in ((3, 14, 8), (3, 15, 0)):
        raise RuntimeError("interpreter_pin")
    catalogue = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "spike").glob("*.py"))}
    (ROOT / "spike" / "CATALOGUE.json").write_text(json.dumps(catalogue, sort_keys=True) + "\n", encoding="ascii")
    # Must be launched with -I -S before any engine process starts.
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError("prestart_census_flags")
    (ROOT / ".s0").mkdir(exist_ok=True)
    (ROOT / ".s0" / "prestart-census.json").write_text(json.dumps(census(), sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()

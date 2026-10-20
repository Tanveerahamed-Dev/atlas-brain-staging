"""Child-process audit witness for the engine's current import surface and output boundary."""
import argparse
import importlib
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--probe", choices=("engine", "inside", "outside", "rename"), default="engine")
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    violations = []
    sys.dont_write_bytecode = True
    mutations = {"os.remove", "os.rmdir", "os.mkdir", "os.rename", "os.link", "os.symlink", "os.chmod", "os.chown", "os.utime", "os.truncate"}
    def audit(event, values):
        paths = []
        if event == "open" and values[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            paths = values[:1]
        elif event in mutations:
            paths = values[:2] if event in {"os.rename", "os.link", "os.symlink"} else values[:1]
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
            paths = [None]
        for path in paths:
            if not isinstance(path, (str, bytes, os.PathLike)) or not Path(os.fsdecode(path)).is_absolute() or not Path(os.fsdecode(path)).resolve().is_relative_to(root):
                violations.append(event)
                raise RuntimeError("non-contract output refused")
    sys.addaudithook(audit)
    try:
        if args.probe == "engine":
            package = importlib.import_module("atlas_brain")
            package_root = Path(package.__file__).parent
            modules = set()
            for source in package_root.rglob("*.py"):
                if source.is_symlink() or not source.resolve().is_relative_to(package_root.resolve()):
                    raise RuntimeError("engine source link refused")
                parts = source.relative_to(package_root).with_suffix("").parts
                parts = parts[:-1] if parts[-1] == "__init__" else parts
                if parts:
                    modules.add(package.__name__ + "." + ".".join(parts))
            for module in sorted(modules):
                importlib.import_module(module)
            if not modules:
                raise RuntimeError("engine witness exercised no modules")
        elif args.probe == "rename":
            target = root / "receipt.json"
            target.write_text("{}", encoding="utf-8")
            target.rename(root.parent / "forbidden")
        else:
            target = root / "receipt.json" if args.probe == "inside" else root.parent / "forbidden"
            target.write_text("{}", encoding="utf-8")
        return int(bool(violations))
    except (RuntimeError, OSError, ImportError):
        print("output witness refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

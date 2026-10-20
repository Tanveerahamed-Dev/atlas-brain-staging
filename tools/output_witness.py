"""Child-process audit witness for the engine's current import surface and output boundary."""
import argparse
import importlib
import os
import re
import subprocess
import sys
from pathlib import Path


def contract_path(path, root: Path, *, directory: bool = False) -> bool:
    """S1 1.12 result-directory grammar; this does not validate payloads or catalogue membership."""
    if not isinstance(path, (str, bytes, os.PathLike)):
        return False
    candidate = Path(os.fsdecode(path))
    if not candidate.is_absolute():
        return False
    try:
        relative = candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return False
    if directory:
        return relative in {"facts", "checks"}
    return (relative in {"result.json", "MANIFEST.sha256"}
            or re.fullmatch(r"facts/[a-z][a-z0-9_]*\.jsonl", relative) is not None
            or re.fullmatch(r"checks/[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.jsonl", relative) is not None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--probe", choices=("engine", "inside", "noncontract", "outside", "rename", "launch", "fork"), default="engine")
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
        if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "os.startfile", "os.startfile/2", "os.link", "os.symlink"}:
            paths = [None]
        for path in paths:
            if not contract_path(path, root, directory=event == "os.mkdir"):
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
        elif args.probe == "launch":
            subprocess.run([sys.executable, "-c", "pass"], check=True)
        elif args.probe == "fork":
            if not hasattr(os, "fork"):
                print("fork probe unavailable")
                return 2
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            os.waitpid(pid, 0)
        elif args.probe == "rename":
            target = root / "result.json"
            target.write_text("{}", encoding="utf-8")
            target.rename(root.parent / "forbidden")
        else:
            target = root / "result.json" if args.probe == "inside" else root / "notes.txt" if args.probe == "noncontract" else root.parent / "forbidden"
            target.write_text("{}", encoding="utf-8")
        return int(bool(violations))
    except (RuntimeError, OSError, ImportError):
        print(f"output witness refused: {violations[-1] if violations else 'engine import failed'}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

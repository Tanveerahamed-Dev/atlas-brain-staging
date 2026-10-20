"""Runtime-only startup baseline and origin/hash-bound import admission."""
import hashlib
import importlib.machinery
import json
from pathlib import Path
import site
import sys
import sysconfig

ROOT = Path(__file__).resolve().parents[1]
INSTALLED = False
RECEIPT = {}


def compare_startup(actual, expected):
    if set(actual) != set(expected):
        raise ValueError("startup_module_baseline:" + json.dumps({"extra": sorted(set(actual) - set(expected)),
                                                                "missing": sorted(set(expected) - set(actual))}))
    return sorted(actual)


def baseline_path():
    environment = "venv" if sys.prefix != sys.base_prefix else "base"
    version = ".".join(str(i) for i in sys.version_info[:3])
    return ROOT / ".s0" / f"startup-{sys.platform}-{version}-{environment}-{sys.flags.no_site}.json"


def allowed_origin(name, origin, stdlib, catalogue, excluded):
    if name in catalogue:
        row = catalogue[name]
        path = Path(origin).resolve() if origin not in (None, "built-in", "frozen") else None
        return path == Path(row["path"]).resolve() and not Path(origin).is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    generated = sysconfig._get_sysconfigdata_name() if hasattr(sysconfig, "_get_sysconfigdata_name") else None
    if name.split(".")[0] not in sys.stdlib_module_names and name not in sys.builtin_module_names and name != generated:
        return False
    if origin in ("built-in", "frozen"):
        return True
    if not origin:
        return False
    path = Path(origin).resolve()
    if any(path.is_relative_to(p.resolve()) for p in excluded):
        return False
    return any(path.is_relative_to(p.resolve()) for p in stdlib)


def install(snapshot, role):
    global INSTALLED, RECEIPT
    from spike import safety
    if INSTALLED:
        return RECEIPT
    # A clean reference is generated only after a -I -S pre-start file census.
    reference_path = baseline_path()
    raw = reference_path.read_bytes()
    reference = json.loads(raw)
    if reference["version"] != sys.version or reference["no_site"] != sys.flags.no_site:
        raise ValueError("startup_interpreter_baseline")
    compare_startup(snapshot, reference[role])
    census = safety.census()
    safety.check_runtime_catalogue()
    hashes = json.loads((ROOT / "spike" / "CATALOGUE.json").read_bytes())
    catalogue = {"spike" if name == "__init__.py" else "spike." + name[:-3]:
                 {"path": str(ROOT / "spike" / name), "sha256": sha} for name, sha in hashes.items()}
    closure = json.loads((ROOT / ".s0" / "import-closure.json").read_bytes())
    for name, row in closure.items():
        catalogue[name] = {"path": str(ROOT / row["path"]), "sha256": row["sha256"]}
    stdlib = [Path(sysconfig.get_path("stdlib")), Path(sysconfig.get_path("platstdlib")),
              Path(sys.base_prefix) / "DLLs", Path(sys.base_prefix) / f"python{sys.version_info.major}{sys.version_info.minor}.zip"]
    excluded = [Path(p) for p in site.getsitepackages()]
    def validate(name, origin):
        if name in ("__main__", "__mp_main__"):
            if role == "worker" and name == "__main__" and origin is None:
                # spawn's -c bootstrap remains __main__ while runpy executes
                # the fixed entry as __mp_main__; the clean role baseline binds it.
                return
            # The fixed entry file is also catalogue-bound before engine imports.
            if origin and Path(origin).resolve().parent == ROOT / "spike":
                name = "spike." + Path(origin).stem
            else:
                raise ValueError("unadmitted_main")
        if not allowed_origin(name, origin, stdlib, catalogue, excluded):
            raise ValueError("import_unadmitted:" + name)
    for name, module in tuple(sys.modules.items()):
        if module is None:
            continue
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None) or getattr(module, "__file__", None)
        validate(name, origin)
    class Fence:
        def find_spec(self, fullname, path=None, target=None):
            spec = (importlib.machinery.BuiltinImporter.find_spec(fullname, path)
                    or importlib.machinery.FrozenImporter.find_spec(fullname, path)
                    or importlib.machinery.PathFinder.find_spec(fullname, path))
            if spec is None:
                if fullname.split(".")[0] in sys.stdlib_module_names:
                    # Portable stdlib code probes platform-specific modules using
                    # try/import/except ImportError (for example fcntl on Windows).
                    return None
                raise ValueError("import_unadmitted:" + fullname)
            validate(fullname, spec.origin)
            return spec
    sys.meta_path.insert(0, Fence())
    RECEIPT = {"startup_baseline_enforced": True, "role": role,
               "baseline_sha256": hashlib.sha256(raw).hexdigest(), "snapshot": sorted(snapshot),
               "clean_reference": reference,
               "startup_census": census, "import_closure_sha256": hashlib.sha256((ROOT / ".s0" / "import-closure.json").read_bytes()).hexdigest(),
               "claim": "stdlib origins and catalogue hashes admitted; startup code detected/refused on host, not prevented"}
    INSTALLED = True
    return RECEIPT

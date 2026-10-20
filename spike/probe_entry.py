import sys
STARTUP_MODULES = tuple(sorted(sys.modules))
from pathlib import Path
ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from spike import safety
safety.install()
from spike.admission import install as admit
admit(STARTUP_MODULES, "worker" if __name__ == "__mp_main__" else "coordinator")


def main():
    import argparse
    import importlib
    import json
    from concurrent.futures import ProcessPoolExecutor
    import multiprocessing as mp
    from spike.runtime import initialize, task, environment
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    records = {"schema": 1, "coordinator": safety.probes(), "worker": [], "retry": []}
    try:
        importlib.import_module("spike.planted_import")
    except safety.EgressDenied:
        records["import_time_denied"] = True
    else:
        records["import_time_denied"] = False
    for role in ("worker", "retry"):
        with ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn"), initializer=initialize,
                                 initargs=(environment(), safety.census(), safety.check_runtime_catalogue())) as pool:
            result = pool.submit(task, {"node": 0, "profile": "access", "fault": "probes"}).result(timeout=120)
            records[role] = result["probes"]
            records[role + "_flags_match"] = result["environment"] == environment()
    records["creations"] = safety.CREATIONS
    records["pass"] = records["import_time_denied"] and all(p["denied"] and p["count"] == 1 for role in ("coordinator", "worker", "retry") for p in records[role]) and all(records[role + "_flags_match"] for role in ("worker", "retry"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(records, sort_keys=True) + "\n", encoding="ascii")
    import hashlib
    args.out.with_suffix(".sha256").write_text(hashlib.sha256(args.out.read_bytes()).hexdigest() + "  " + args.out.name + "\n", encoding="ascii")
    sys.exit(0 if records["pass"] else 1)


if __name__ == "__main__":
    main()

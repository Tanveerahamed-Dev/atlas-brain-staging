"""Separate diagnostic: four fixed lanes, 75 real device tasks per lane."""
import sys
STARTUP_MODULES = tuple(sorted(sys.modules))
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from spike import safety
safety.install()
from spike.admission import install as admit
admit(STARTUP_MODULES, "worker" if __name__ == "__mp_main__" else "coordinator")

from concurrent.futures import ProcessPoolExecutor
import json
import multiprocessing as mp
import os
import time
from spike.runtime import environment, initialize, task
from tools.scale.workload import canonical, digest, verify

TASKS = 0


def observed_task(payload):
    global TASKS
    value = task(payload)
    TASKS += 1
    control = Path(payload["control"])
    identity = ".".join(str(i) for i in mp.current_process()._identity)
    token = f"{os.getpid()}-{identity}-{TASKS}"
    marker = control / (token + ".ready")
    temporary = marker.with_suffix(".tmp")
    temporary.write_bytes(canonical({"pid": os.getpid(), "identity": identity, "ordinal": TASKS, "node": payload["node"]}))
    temporary.replace(marker)
    # The external sampler takes three quiet 20 Hz samples before release.
    # No GC, allocator trim, synthetic allocation or in-worker psutil is used.
    while not (control / (token + ".ack")).exists():
        time.sleep(0.01)
    if safety.VIOLATIONS:
        raise RuntimeError("growth_egress_violation")
    return {"pid": value["pid"], "identity": identity, "node": payload["node"], "facts": value["facts"]}


def main():
    root, output, control = (Path(v).resolve() for v in sys.argv[1:4])
    recycle = None if sys.argv[4] == "none" else int(sys.argv[4])
    doc = verify(root)
    if doc["size"] != 300:
        raise ValueError("growth_requires_300")
    output.mkdir()
    grouped = [[] for _ in range(300)]
    for item in doc["artifacts"]:
        grouped[item["node"]].append(item)
    estate_hash = digest((root / "ESTATE.json").read_bytes())
    census, catalogue = safety.census(), safety.check_runtime_catalogue()
    pools = [ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn"),
                                max_tasks_per_child=recycle, initializer=initialize,
                                initargs=(environment(), census, catalogue, str(control))) for _ in range(4)]
    results = []
    try:
        for first in range(0, 300, 4):
            futures = []
            for lane, node in enumerate(range(first, first + 4)):
                payload = {"node": node, "profile": grouped[node][0]["profile"], "root": str(root),
                           "stp_expected_root": doc["intent"]["stp_root_mac"][str(node)],
                           "stp_expected_vlan": doc["intent"]["stp_vlan"],
                           "stp_intent_ref": [estate_hash, f"/intent/stp_root_mac/{node}"],
                           "expected_route": doc["intent"]["expected_route"],
                           "route_intent_ref": [estate_hash, "/intent/expected_route"],
                           "pending": str(output), "captures": grouped[node], "control": str(control),
                           "fault": "none", "queued_ns": time.perf_counter_ns()}
                futures.append(pools[lane].submit(observed_task, payload))
            results.extend(future.result() for future in futures)
        (control / "completed.json").write_bytes(canonical({"tasks": results, "recycle": recycle}))
    finally:
        for pool in pools:
            pool.shutdown(wait=True, cancel_futures=True)


if __name__ == "__main__":
    main()

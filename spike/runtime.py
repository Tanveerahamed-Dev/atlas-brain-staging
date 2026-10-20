"""Disposable S0 pipeline. Never merge this package into product main."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
import gc
import json
import multiprocessing as mp
import os
from pathlib import Path
import pickle
import shutil
import signal
import sys
import time
import uuid

from spike import safety
from tools.scale.workload import canonical, digest, load_spec, strict_json, verify

_PARENT = None
_START = 0


def write_node(path, value):
    # Serialize directly into the unpublished file. Avoid keeping the full
    # JSON string and encoded bytes beside the device's complete fact rows.
    with path.open("w", encoding="ascii", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        stream.write("\n")
    return path.stat().st_size


def environment():
    return {"flags": list(sys.flags), "path": sys.path, "cwd": os.getcwd(),
            "env": {k: os.environ.get(k) for k in ("TZ", "LANG", "LC_ALL", "PYTHONHASHSEED")},
            "hash_witness": hash("atlas-brain-fixed-seed") if not sys.flags.ignore_environment else None}


def verify_manual_isolation(args):
    expected_randomization = 0 if args.expected_seed == "0" else 1
    if not (sys.flags.isolated == 0 and sys.flags.ignore_environment == 0 and sys.flags.no_user_site == 1
            and sys.flags.safe_path and sys.flags.dont_write_bytecode == 1
            and sys.flags.hash_randomization == expected_randomization
            and os.environ.get("PYTHONHASHSEED") == args.expected_seed
            and hash("atlas-brain-fixed-seed") == args.expected_hash):
        raise ValueError("manual_isolation_or_seed_mismatch")
    if "PYTHONPATH" in os.environ or "PYTHONHOME" in os.environ or "" in sys.path:
        raise ValueError("manual_isolation_path_leak")


def initialize(expected, expected_census, expected_catalogue, control=None):
    global _PARENT, _START
    from spike.admission import require
    require()
    safety.install(worker=True)
    _START = time.perf_counter_ns()
    _PARENT = expected
    if environment() != expected:
        print(json.dumps({"worker_environment_mismatch": {"expected": expected, "actual": environment()}}, sort_keys=True), file=sys.stderr, flush=True)
        raise ValueError("worker_environment_mismatch")
    if safety.census() != expected_census or safety.check_runtime_catalogue() != expected_catalogue:
        raise ValueError("worker_admission_mismatch")
    if control is not None:
        from spike import metrics
        metrics.install(control)


def _fault(payload):
    if payload["node"] != 18:
        return
    fault = payload["fault"]
    if fault in ("kill-once", "kill-twice"):
        mark = Path(payload["control"]) / f"kill-{payload['node']}"
        count = int(mark.read_text(encoding="ascii")) if mark.exists() else 0
        if count < (1 if fault == "kill-once" else 2):
            mark.write_text(str(count + 1), encoding="ascii")
            # Test-only abrupt worker death; includes Windows TerminateProcess equivalent exit.
            if os.name == "nt":
                import _winapi
                _winapi.TerminateProcess(_winapi.GetCurrentProcess(), 97)
            else:
                os.kill(os.getpid(), signal.SIGKILL)
    if fault == "memory":
        raise MemoryError("planted")
    if fault == "import-probe":
        import importlib
        importlib.import_module("spike.planted_import")
    if fault in ("admission-probe", "admission-swallow"):
        import importlib
        if fault == "admission-swallow":
            try:
                importlib.import_module("startup_unlisted_probe")
            except BaseException:
                pass  # Counter must still refuse publication.
        else:
            importlib.import_module("startup_unlisted_probe")
    if fault == "swallow-probe":
        import socket
        try:
            socket.socket(socket.AF_INET)
        except BaseException:
            pass  # Planted broad swallow: the task's counter must still fail the run.
    if fault == "pack":
        raise RuntimeError("planted_pack")


def task(payload):
    start, cpu = time.perf_counter_ns(), time.process_time_ns()
    from spike.parsers import parse_capture
    name = f"sw-{payload['node']:05d}"
    try:
        _fault(payload)
    except RuntimeError:
        (Path(payload["pending"]) / f"{name}.json").write_bytes(canonical({"schema": 1, "node": name, "state": "unknown", "reason": "ANALYSIS_FAILED", "facts": []}))
        return {"name": name, "profile": payload["profile"], "estate_rows": [], "route_summary": {"complete": False, "expected_present": False, "evidence": []},
                "analysis_failed": True, "facts": 0, "pid": os.getpid(), "violations": safety.VIOLATIONS, "wall_ns": time.perf_counter_ns() - start, "cpu_ns": time.process_time_ns() - cpu}
    if payload["fault"] == "probes":
        records = safety.probes()
        return {"probes": records, "environment": environment(), "pid": os.getpid(), "violations": safety.VIOLATIONS}
    facts, refs, estate, accounts = [], [], [], []
    route_summary = {"complete": False, "expected_present": False, "evidence": []}
    total_rows = 0
    keep = {"interface", "interface_attributes", "system_mtu", "native", "channel", "interface_mtu", "neighbor", "trunk", "root_priority", "bridge_priority", "root_address", "bridge_address", "router_id", "ospf_neighbor", "ospf_network"}
    for index, item in enumerate(payload["captures"]):
        body = (Path(payload["root"]) / item["path"]).read_bytes()
        if digest(body) != item["sha256"] or len(body) != item["bytes"]:
            raise ValueError("capture_changed")
        parsed = parse_capture(load_spec()["profiles"][payload["profile"]]["family"], item["form"], body)
        if parsed["unrecognized"]:
            raise ValueError("parse_partial")
        refs.append([item["path"], item["sha256"], item["bytes"]])
        accounts.append([index, parsed["accounting"]])
        for row in parsed["rows"]:
            # Evidence is interned per artifact. Every fact resolves to its hash and span.
            facts.append([row.kind, row.values, index, row.start, row.end, row.line])
            reference = [item["sha256"], row.start, row.end, row.line]
            if row.kind in keep:
                estate.append([row.kind, row.values, reference])
            if row.kind == "route" and row.values[0] == payload["expected_route"]["vrf"] and row.values[2] == payload["expected_route"]["prefix"]:
                route_summary["expected_present"] = True
        if item["form"] == "routes" and parsed["accounting"]["unclaimed"] == 0:
            route_summary["complete"] = any(r.kind == "vrf" and r.values[0] == payload["expected_route"]["vrf"] for r in parsed["rows"])
            route_summary["evidence"] = [[item["sha256"], 0, len(body), 1], payload["route_intent_ref"]]
        total_rows += len(parsed["rows"])
    result = {"schema": 1, "node": name, "captures": refs, "facts": facts, "accounting": accounts}
    written = write_node(Path(payload["pending"]) / f"{name}.json", result)
    return {"name": name, "profile": payload["profile"], "estate_rows": estate, "route_summary": route_summary,
            "stp_expected_root": payload["stp_expected_root"], "stp_intent_ref": payload["stp_intent_ref"],
            "stp_expected_vlan": payload["stp_expected_vlan"],
            "facts": total_rows, "bytes": written, "pid": os.getpid(), "violations": safety.VIOLATIONS,
            "environment": environment(), "wall_ns": time.perf_counter_ns() - start, "cpu_ns": time.process_time_ns() - cpu,
            "process_cpu_ns": time.process_time_ns(), "initializer_to_task_ns": start - _START,
            "imports": sorted(safety.IMPORTS),
            "absent_imports": sorted(__import__("spike.admission", fromlist=["ABSENT_IMPORTS"]).ABSENT_IMPORTS),
            "ready_latency_ns": start - payload["queued_ns"], "gc": gc.get_stats()}


def pool_run(payloads, workers, recycle, expected, census, catalogue, progress, pause_at_half=False):
    completed, pending, failures = [], [], []
    pool = ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context("spawn"),
                               max_tasks_per_child=recycle, initializer=initialize, initargs=(expected, census, catalogue, str(progress.parent)))
    broken = False
    try:
        futures = {}
        for item in payloads:
            item["queued_ns"] = time.perf_counter_ns()
            futures[pool.submit(task, item)] = item
        for future in as_completed(futures):
            payload = futures[future]
            try:
                result = future.result()
            except BrokenProcessPool:
                broken = True
                pending.append(payload)
                continue
            except MemoryError:
                failures.append({"node": payload["node"], "class": "MemoryError"})
                raise
            completed.append(result)
            progress.write_bytes(canonical({"completed": len(completed), "total": len(payloads)}))
            if pause_at_half and len(completed) == len(payloads) // 2:
                while True:
                    time.sleep(0.05)  # Test-only cancellation barrier; never in normal runs.
    except BaseException:
        pool.kill_workers()
        raise
    finally:
        if broken:
            pool.kill_workers()
        else:
            pool.shutdown(wait=True, cancel_futures=True)
    return completed, pending, failures


def execute(args, startup_modules):
    from spike import admission
    admission.require()
    from spike.estate import estate_stages, CHECKS
    if sys.version_info[:3] not in ((3, 14, 8), (3, 15, 0)):
        raise ValueError("interpreter_pin")
    if args.manual_isolation:
        verify_manual_isolation(args)
    elif not sys.flags.isolated:
        raise ValueError("isolation_required")
    if args.out.exists():
        raise FileExistsError("result_exists")
    stages = {}
    def measured(name, fn):
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        value = fn()
        stages[name] = {"wall_ns": time.perf_counter_ns() - wall, "cpu_ns": time.process_time_ns() - cpu, "gc": gc.get_stats()}
        return value
    doc = measured("intake", lambda: verify(args.root))
    census, catalogue = safety.census(), safety.check_runtime_catalogue()
    worker_count = min(os.process_cpu_count() or 1, 61, args.workers)
    args.control.mkdir(parents=True, exist_ok=True)
    pending = args.out.with_name(".pending-" + uuid.uuid4().hex)
    pending.mkdir()
    began = time.perf_counter_ns()
    try:
        grouped = [[] for _ in range(doc["size"])]
        for item in doc["artifacts"]:
            grouped[item["node"]].append(item)
        estate_hash = digest((args.root / "ESTATE.json").read_bytes())
        payloads = [{"node": i, "profile": items[0]["profile"], "root": str(args.root.absolute()),
                     "stp_expected_root": doc["intent"]["stp_root_mac"][str(i)],
                     "stp_expected_vlan": doc["intent"]["stp_vlan"],
                     "stp_intent_ref": [estate_hash, f"/intent/stp_root_mac/{i}"],
                     "expected_route": doc["intent"]["expected_route"], "route_intent_ref": [estate_hash, "/intent/expected_route"],
                     "pending": str(pending.resolve()), "captures": items, "control": str(args.control.resolve()), "fault": args.fault} for i, items in enumerate(grouped)]
        transfer_wall = time.perf_counter_ns()
        task_bytes = sum(len(pickle.dumps(item)) for item in payloads)
        if max(len(pickle.dumps(item)) for item in payloads) > 65536:
            raise ValueError("task_payload_budget")
        serialize_ns = time.perf_counter_ns() - transfer_wall
        from spike import metrics
        metrics.install(None)
        def devices():
            if args.pause_before_workers:
                (args.control / "before-workers.ready").write_text("ready\n", encoding="ascii")
                while not (args.control / "before-workers.release").exists():
                    time.sleep(0.01)
            results, retry, failures = pool_run(payloads, worker_count, args.recycle, environment(), census, catalogue, args.control / "progress.json", args.pause_at_half)
            if retry:
                second, failed, extra = pool_run(retry, 1, args.recycle, environment(), census, catalogue, args.control / "retry-progress.json")
                if failed:
                    raise RuntimeError("second_worker_failure")
                results.extend(second)
            return sorted(results, key=lambda item: item["name"])
        nodes = measured("device", devices)
        queue_metrics = [metrics.snapshot()] + [strict_json(p.read_bytes()) for p in sorted(args.control.glob("worker-metrics-*.json"))]
        queue_ns = sum(m["dump_ns"] + m["load_ns"] for m in queue_metrics)
        worker_cpu = {}
        for node in nodes:
            worker_cpu[node["pid"]] = max(worker_cpu.get(node["pid"], 0), node.get("process_cpu_ns", 0))
        stages["device"]["coordinator_cpu_ns"] = stages["device"]["cpu_ns"]
        stages["device"]["worker_cpu_ns_through_last_task"] = sum(worker_cpu.values())
        stages["device"]["worker_finalized_cpu_ns"] = sum(m["process_cpu_ns"] for m in queue_metrics[1:])
        stages["device"]["cpu_ns"] += stages["device"]["worker_finalized_cpu_ns"]
        if any(node["violations"] for node in nodes) or safety.VIOLATIONS:
            raise RuntimeError("egress_violation")
        estate = measured("estate", lambda: estate_stages(nodes))
        for node in nodes:
            if node.get("analysis_failed"):
                estate["checks"].extend([[check, node["name"], "node", "unknown", [], "ANALYSIS_FAILED"] for check in CHECKS])
        estate["checks"].sort()
        def publish():
            (pending / "estate.json").write_bytes(canonical(estate))
            entries = []
            for path in sorted(pending.iterdir()):
                entries.append(f"{digest(path.read_bytes())}  {path.name}\n")
            (pending / "MANIFEST.sha256").write_bytes("".join(entries).encode("ascii"))
            pending.rename(args.out)
        measured("output", publish)
        receipt = {"schema": 1, "status": "ok", "size": doc["size"], "dense": doc["dense"], "stages": stages,
                   "wall_ns": time.perf_counter_ns() - began, "facts": sum(n["facts"] for n in nodes),
                   "result_bytes": sum(p.stat().st_size for p in args.out.iterdir()), "task_bytes": task_bytes,
                   "serialization_probe_ns": serialize_ns, "pickling_share": queue_ns / stages["device"]["wall_ns"],
                   "pickling_note": "aggregate queue dumps+loads duration / device wall (conservative wall-equivalent; excludes spawn bootstrap pickle)",
                   "queue_metrics": queue_metrics,
                   "result_payload_bytes": sum(len(pickle.dumps(n)) for n in nodes),
                   "facts_per_device": [[n["name"], n["facts"]] for n in nodes],
                   "bytes_per_fact": sum(n.get("bytes", 0) for n in nodes) / max(1, sum(n["facts"] for n in nodes)),
                   "worker_startup": {"metric": "first-task ready latency includes task submission and admission", "ready_ns_by_pid": [[pid, min(n.get("ready_latency_ns", 0) for n in nodes if n["pid"] == pid)] for pid in sorted(worker_cpu)]},
                   "manifest_sha256": digest((args.out / "MANIFEST.sha256").read_bytes()),
                   "runtime": {"version": sys.version, "environment": environment(), "workers": worker_count,
                               "profile": "fixed-seed probes under equivalent manual isolation, not -I" if args.manual_isolation else "-I acceptance",
                               "requested_hash_seed": os.environ.get("PYTHONHASHSEED"), "hash_seed_effective": args.expected_seed if args.manual_isolation else "random (-I ignores PYTHONHASHSEED)",
                               "startup_modules": startup_modules, "startup_census": census,
                               "catalogue": catalogue, "imports": sorted(safety.IMPORTS), "creations": safety.CREATIONS,
                               "startup_baseline_enforced": admission.INSTALLED,
                               "interpreter": {"executable": sys.executable, "prefix": sys.prefix, "base_prefix": sys.base_prefix,
                                               "venv": sys.prefix != sys.base_prefix},
                               "worker_imports": sorted({name for n in nodes for name in n.get("imports", [])}),
                               "absent_imports": sorted(admission.ABSENT_IMPORTS),
                               "worker_absent_imports": sorted({name for n in nodes for name in n.get("absent_imports", [])}),
                               "admission": admission.RECEIPT},
                   "workers": [{k: v for k, v in n.items() if k not in ("estate_rows", "route_summary")} for n in nodes]}
        if sys.platform == "linux":
            peak = Path("/sys/fs/cgroup/memory.peak")
            if peak.exists():
                receipt["cgroup_peak_before_receipt"] = int(peak.read_text(encoding="ascii"))
        args.receipt.write_bytes(canonical(receipt))
    finally:
        if pending.exists():
            shutil.rmtree(pending)


def main(startup_modules):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--control", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--recycle", type=int)
    parser.add_argument("--pause-at-half", action="store_true")
    parser.add_argument("--pause-before-workers", action="store_true")
    parser.add_argument("--manual-isolation", action="store_true")
    parser.add_argument("--expected-seed", choices=("0", "4242"))
    parser.add_argument("--expected-hash", type=int)
    parser.add_argument("--fault", default="none", choices=("none", "kill-once", "kill-twice", "memory", "pack", "import-probe", "swallow-probe", "admission-probe", "admission-swallow"))
    args = parser.parse_args()
    if args.manual_isolation and (args.expected_seed is None or args.expected_hash is None):
        parser.error("manual probes require an independently measured seed witness")
    if args.workers < 1 or (args.recycle is not None and args.recycle < 1):
        parser.error("positive worker and recycle counts required")
    def cancel(signum, frame):
        raise KeyboardInterrupt("cancelled")
    signal.signal(signal.SIGTERM, cancel)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, cancel)
    try:
        execute(args, startup_modules)
    except BaseException as exc:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_bytes(canonical({"schema": 1, "status": "failed", "failure": type(exc).__name__, "code": str(exc)[:120], "creations": safety.CREATIONS}))
        raise

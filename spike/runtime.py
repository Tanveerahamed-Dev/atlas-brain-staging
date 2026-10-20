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


def environment():
    return {"flags": list(sys.flags), "path": sys.path, "cwd": os.getcwd(),
            "env": {k: os.environ.get(k) for k in ("TZ", "LANG", "LC_ALL")}}


def initialize(expected, expected_census, expected_catalogue):
    global _PARENT, _START
    safety.install(worker=True)
    _START = time.perf_counter_ns()
    _PARENT = expected
    if environment() != expected:
        raise ValueError("worker_environment_mismatch")
    if safety.census() != expected_census or safety.check_runtime_catalogue() != expected_catalogue:
        raise ValueError("worker_admission_mismatch")


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
            os._exit(97)
    if fault == "memory":
        raise MemoryError("planted")
    if fault == "pack":
        raise RuntimeError("planted_pack")


def task(payload):
    start, cpu = time.perf_counter_ns(), time.process_time_ns()
    from spike.parsers import parse_capture
    name = f"sw-{payload['node']:05d}"
    try:
        _fault(payload)
    except RuntimeError:
        return {"name": name, "profile": payload["profile"], "estate_rows": [], "route_summary": {"complete": False, "expected_present": False, "evidence": []},
                "analysis_failed": True, "facts": 0, "pid": os.getpid(), "violations": safety.VIOLATIONS, "wall_ns": time.perf_counter_ns() - start, "cpu_ns": time.process_time_ns() - cpu}
    if payload["fault"] == "probes":
        records = safety.probes()
        return {"probes": records, "environment": environment(), "pid": os.getpid(), "violations": safety.VIOLATIONS}
    facts, refs, estate, accounts = [], [], [], []
    route_summary = {"complete": False, "expected_present": False, "evidence": []}
    total_rows = 0
    keep = {"interface", "interface_attributes", "system_mtu", "native", "channel", "interface_mtu", "neighbor", "trunk", "root_priority", "bridge_priority", "ospf_neighbor", "ospf_network"}
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
            if row.kind == "route" and row.values[2] == "203.0.113.0/32":
                route_summary["expected_present"] = True
        if item["form"] == "routes" and parsed["accounting"]["unclaimed"] == 0:
            route_summary["complete"] = True
            route_summary["evidence"] = [[item["sha256"], 0, len(body), 1]]
        total_rows += len(parsed["rows"])
    result = {"schema": 1, "node": name, "captures": refs, "facts": facts, "accounting": accounts}
    raw = canonical(result)
    (Path(payload["pending"]) / f"{name}.json").write_bytes(raw)
    return {"name": name, "profile": payload["profile"], "estate_rows": estate, "route_summary": route_summary,
            "facts": total_rows, "bytes": len(raw), "pid": os.getpid(), "violations": safety.VIOLATIONS,
            "environment": environment(), "wall_ns": time.perf_counter_ns() - start, "cpu_ns": time.process_time_ns() - cpu,
            "startup_ns": start - _START, "gc": gc.get_stats()}


def pool_run(payloads, workers, recycle, expected, census, catalogue, progress):
    completed, pending, failures = [], [], []
    pool = ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context("spawn"),
                               max_tasks_per_child=recycle, initializer=initialize, initargs=(expected, census, catalogue))
    futures = {pool.submit(task, item): item for item in payloads}
    broken = False
    try:
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
    from spike.estate import estate_stages, CHECKS
    if sys.version_info[:3] not in ((3, 14, 8), (3, 15, 0)):
        raise ValueError("interpreter_pin")
    if not sys.flags.isolated:
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
        payloads = [{"node": i, "profile": items[0]["profile"], "root": str(args.root.resolve()),
                     "pending": str(pending.resolve()), "captures": items, "control": str(args.control.resolve()), "fault": args.fault} for i, items in enumerate(grouped)]
        transfer_wall = time.perf_counter_ns()
        task_bytes = sum(len(pickle.dumps(item)) for item in payloads)
        if max(len(pickle.dumps(item)) for item in payloads) > 65536:
            raise ValueError("task_payload_budget")
        serialize_ns = time.perf_counter_ns() - transfer_wall
        def devices():
            results, retry, failures = pool_run(payloads, worker_count, args.recycle, environment(), census, catalogue, args.control / "progress.json")
            if retry:
                second, failed, extra = pool_run(retry, 1, args.recycle, environment(), census, catalogue, args.control / "retry-progress.json")
                if failed:
                    raise RuntimeError("second_worker_failure")
                results.extend(second)
            return sorted(results, key=lambda item: item["name"])
        nodes = measured("device", devices)
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
                   "serialization_probe_ns": serialize_ns, "pickling_share": None,
                   "pickling_note": "serialization probe only; executor serialization share not instrumented",
                   "result_payload_bytes": sum(len(pickle.dumps(n)) for n in nodes),
                   "manifest_sha256": digest((args.out / "MANIFEST.sha256").read_bytes()),
                   "runtime": {"version": sys.version, "environment": environment(), "workers": worker_count,
                               "requested_hash_seed": os.environ.get("PYTHONHASHSEED"), "hash_seed_effective": "random (-I ignores PYTHONHASHSEED)",
                               "startup_modules": startup_modules, "startup_census": census,
                               "catalogue": catalogue, "imports": sorted(safety.IMPORTS), "creations": safety.CREATIONS,
                               "startup_baseline_enforced": False},
                   "workers": [{k: v for k, v in n.items() if k not in ("estate_rows", "route_summary")} for n in nodes]}
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
    parser.add_argument("--fault", default="none", choices=("none", "kill-once", "kill-twice", "memory", "pack"))
    args = parser.parse_args()
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
        args.receipt.write_bytes(canonical({"schema": 1, "status": "failed", "failure": type(exc).__name__, "code": str(exc)[:120]}))
        raise

"""External 20 Hz RSS/USS probe with first-task barriers and explicit PID identity."""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def decide(rows, workers, tasks):
    if len(rows) != workers or len({(r["pid"], r.get("identity")) for r in rows}) != workers or any(
            r["tasks"] != tasks or r["baseline_rss"] <= 0
            or r["sampled_peak_rss"] < r["plateau_peak_rss"]
            or r["plateau_peak_rss"] < r["baseline_rss"] for r in rows):
        raise ValueError("incomplete_growth")
    ratios = [(r["plateau_peak_rss"] - r["baseline_rss"]) / r["baseline_rss"] for r in rows]
    transient = [(r["sampled_peak_rss"] - r["baseline_rss"]) / r["baseline_rss"] for r in rows]
    return {"recycling_required": any(ratio > 0.25 for ratio in ratios),
            "max_growth_fraction": max(ratios), "max_transient_growth_fraction": max(transient), "threshold": 0.25}


def probe(runtime, source, raw, recycle):
    import psutil
    from tools.scale.measure import FLAGS, kill_tree, result_snapshot, sample_memory
    from tools.scale.workload import canonical
    raw.mkdir()
    control = raw / "control"
    control.mkdir()
    output = raw / "device-results"
    console = (raw / "console.log").open("wb")
    process = subprocess.Popen([str(runtime.absolute())] + FLAGS + [str(ROOT / "spike" / "growth_entry.py"),
                               str(source), str(output), str(control), recycle], stdout=console, stderr=subprocess.STDOUT)
    parent = psutil.Process(process.pid)
    known, rows, samples, plateau = {}, {}, [], {}
    last_progress = time.monotonic()
    try:
        while process.poll() is None:
            stamp = time.monotonic()
            try:
                known.update({p.pid: p for p in parent.children(recursive=True)})
            except psutil.NoSuchProcess:
                continue  # The next poll records the actual exit status.
            tick = {}
            for pid, child in list(known.items()):
                try:
                    memory, race = sample_memory(child)
                except (psutil.NoSuchProcess, ProcessLookupError):
                    continue
                if memory is None:
                    continue
                tick[pid] = {"rss": memory.rss, "uss": memory.uss}
                for row in rows.values():
                    if row["pid"] == pid and row["process_create_time"] == child.create_time():
                        row["sampled_peak_rss"] = max(row["sampled_peak_rss"], memory.rss)
                        row["sampled_peak_uss"] = max(row["sampled_peak_uss"], memory.uss)
            samples.append({"t": stamp, "pids": tick})
            for marker in control.glob("*.ready"):
                ack = marker.with_suffix(".ack")
                if ack.exists():
                    continue
                record = json.loads(marker.read_bytes())
                pid = record["pid"]
                if pid not in tick:
                    raise ValueError("live_barrier_worker_not_sampled")
                values = plateau.setdefault(marker.name, [])
                values.append(tick[pid])
                if len(values) < 3:
                    continue
                rss = statistics.median(v["rss"] for v in values)
                uss = statistics.median(v["uss"] for v in values)
                key = (pid, record["identity"])
                row = rows.setdefault(key, {"pid": pid, "identity": record["identity"],
                                           "process_create_time": known[pid].create_time(), "baseline_rss": rss, "baseline_uss": uss,
                                           "sampled_peak_rss": max(v["rss"] for v in values),
                                           "sampled_peak_uss": max(v["uss"] for v in values),
                                           "plateau_peak_rss": rss, "plateau_peak_uss": uss, "tasks": 0})
                if record["ordinal"] != row["tasks"] + 1:
                    raise ValueError("worker_task_sequence")
                row["tasks"] += 1
                row["plateau_peak_rss"] = max(row["plateau_peak_rss"], rss)
                row["plateau_peak_uss"] = max(row["plateau_peak_uss"], uss)
                ack.write_text("sampled\n", encoding="ascii")
                last_progress = stamp
            if stamp - last_progress > 120:
                raise TimeoutError("growth_watchdog")
            time.sleep(max(0, 0.05 - (time.monotonic() - stamp)))
        if process.returncode:
            raise ValueError("growth_child_failed")
        time.sleep(5)
        for member in known.values():
            try:
                if member.is_running() and member.status() != psutil.STATUS_ZOMBIE:
                    raise ValueError("growth_orphan")
            except psutil.NoSuchProcess:
                pass
        summary = json.loads((control / "completed.json").read_bytes())
        expected_workers, expected_tasks = (4, 75) if recycle == "none" else (100, 3)
        verdict = decide(list(rows.values()), expected_workers, expected_tasks)
        if len(summary["tasks"]) != 300:
            raise ValueError("incomplete_growth_tasks")
        (raw / "summary.json").write_bytes(canonical({"rows": list(rows.values()), "verdict": verdict,
                                                       "diagnostic_only": True, "recycle": recycle}))
        return verdict, result_snapshot(output)
    finally:
        if process.poll() is None:
            kill_tree(known)
            process.kill()
            process.wait()
        console.close()
        (raw / "samples.json").write_bytes(canonical(samples))
        (raw / "barriers.json").write_bytes(canonical(plateau))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    args = parser.parse_args()
    from tools.scale.measure import measure, shape, result_snapshot
    from tools.scale.workload import canonical, digest, generate
    source = ROOT / ".s0" / "input-300"
    generate(source, 300, False)
    args.raw.mkdir(parents=True)
    baseline = measure(source, args.raw / "normal", args.runtime, 300, cap=0, keep_result=True)
    if baseline["status"] != "ok":
        raise ValueError("growth_normal_baseline_failed")
    expected = {k: v for k, v in result_snapshot(args.raw / "normal" / "result").items() if k.startswith("sw-")}
    decisions = {}
    for mode in ("none", "3"):
        verdict, actual = probe(args.runtime, source, args.raw / mode, mode)
        if expected != actual:
            raise ValueError("growth_device_bytes_differ")
        decisions[mode] = verdict
    required = decisions["none"]["recycling_required"]
    value = 3 if required and not decisions["3"]["recycling_required"] else None
    receipt = {"schema": 1, "runner": shape(), "decisions": decisions, "recycling_required": required,
               "measured_candidate": value, "owner_selected_default": None,
               "decision_closed": not required,
               "scope": "separate barrier diagnostic, four fixed lanes of 75 actual WL-1 device tasks; not speed/CV acceptance",
               "baseline": "median of three external 20 Hz quiet post-first-task samples; no forced GC or allocator trim",
               "comparison": "owner-clarified accumulation: maximum quiet post-task RSS versus first-task plateau; transient RSS/USS peaks retained separately",
               "plan_clarification": "2026-10-20 owner: S3 line 222 measures post-task resident accumulation; per-task transient peaks are governed by the separate hard S0-a cap",
               "device_bytes_equal_normal_run": True}
    (args.raw / "decision.json").write_bytes(canonical(receipt))
    paths = [p for p in args.raw.rglob("*") if p.is_file()]
    (args.raw / "RAW.sha256").write_text("".join(f"{digest(p.read_bytes())}  {p.relative_to(args.raw).as_posix()}\n" for p in sorted(paths)), encoding="ascii")
    if not receipt["decision_closed"]:
        raise ValueError("owner_selected_none_exceeds_post_task_growth_threshold")


if __name__ == "__main__":
    main()

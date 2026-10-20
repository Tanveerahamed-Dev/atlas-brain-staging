"""No extrapolated 4-vCPU verdict; missing evidence is never a pass."""
import argparse
import json
import math
from pathlib import Path
import statistics


def judge(rows):
    missing, breaches, aggregates = [], [], []
    for os_name in ("Linux", "Windows"):
        for size in (100, 300, 1000):
            selected = [r for r in rows if r.get("os") == os_name and r.get("size") == size and not r.get("dense")]
            valid = [r for r in selected if r.get("status") == "ok"]
            if len(valid) != 5:
                missing.append(f"{os_name}/{size}: need 5 successful timed runs, got {len(valid)}")
            if valid:
                values = [r["wall_s"] for r in valid]
                aggregates.append({"os": os_name, "size": size, "n": len(values), "median_s": statistics.median(values), "max_s": max(values),
                                   "peak_tree_uss": max(r.get("peak_tree_uss", 0) for r in valid),
                                   "median_tree_uss": statistics.median([r.get("median_tree_uss", 0) for r in valid])})
                if size == 1000:
                    if statistics.median(values) > 150 or max(values) > 180:
                        breaches.append(f"{os_name}: full-volume wall budget")
                    for name, budget in (("intake", 15), ("device", 80), ("estate", 45), ("output", 10)):
                        stage_values = [r.get("stages", {}).get(name, {}).get("wall_ns") for r in valid]
                        if any(v is None for v in stage_values):
                            missing.append(f"{os_name}: stage {name}")
                        elif any(v / 1e9 > budget for v in stage_values):
                            breaches.append(f"{os_name}: {name} stage budget")
            for row in selected:
                if row.get("cap_bytes") != 2**31 or row.get("cap_verified") is not True:
                    missing.append(f"{os_name}/{size}: hard 2 GiB cap not verified")
        dense = [r for r in rows if r.get("os") == os_name and r.get("dense") and r.get("size") == 1000 and r.get("status") == "ok"]
        if len(dense) != 1:
            missing.append(f"{os_name}: need one dense run")
        elif dense[0]["wall_s"] > 300 or dense[0].get("cap_bytes") != 4 * 2**30 or not dense[0].get("cap_verified"):
            breaches.append(f"{os_name}: dense budget/cap")
        for stage in ("intake", "device", "estate", "output"):
            stages = {}
            for size in (300, 1000):
                times = [r.get("stages", {}).get(stage, {}).get("wall_ns") for r in rows if r.get("status") == "ok" and r.get("os") == os_name and r.get("size") == size and not r.get("dense")]
                if len(times) == 5 and all(t is not None for t in times):
                    stages[size] = statistics.median(times) / 1e9
            if len(stages) == 2 and max(stages.values()) >= 2:
                exponent = math.log(stages[1000] / stages[300]) / math.log(1000 / 300)
                aggregates.append({"os": os_name, "stage": stage, "scaling_exponent": exponent})
                if exponent > 1.3:
                    breaches.append(f"{os_name}: {stage} superlinear algorithm")
    full = [r.get("manifest_sha256") for r in rows if r.get("size") == 1000 and not r.get("dense") and r.get("status") == "ok"]
    if len(full) == 10 and (None in full or len(set(full)) != 1):
        breaches.append("full-volume determinism")
    failures = [r for r in rows if r.get("status") != "ok"]
    reference = bool(rows) and all(r.get("runner", {}).get("cpu_count") == 4 and r.get("runner", {}).get("memory_bytes", 0) >= 15 * 2**30 for r in rows)
    if not reference:
        missing.append("4-vCPU/16-GB reference runner")
    return {"schema": 1, "reference_verdict": "pass" if not missing and not failures and not breaches else "not_verified",
            "observed_status": "failed" if failures or breaches else "partial" if missing else "pass",
            "missing": missing, "breaches": breaches, "aggregates": aggregates,
            "language_verdict": "not_verified (bounded profiling and S0-b remain separate)"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    rows = [json.loads(p.read_bytes()) for p in sorted(args.raw.rglob("measurement.json"))]
    args.out.write_text(json.dumps(judge(rows), indent=2) + "\n", encoding="ascii")

"""S0-c/d matrix driver. No schedule-dependent result is ever accepted."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.scale.measure import measure
from tools.scale.workload import canonical, digest, generate, verify


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("determinism", "stability", "faults"))
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--interpreter", default="3.14.8")
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--recycle", choices=("none", "3"), default="none")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()
    input_root = ROOT / ".s0" / "input-300"
    if not input_root.exists():
        generate(input_root, 300, False)
    else:
        verify(input_root)
    args.raw.mkdir(parents=True, exist_ok=False)
    rows, expected_digest = [], None
    if args.mode == "determinism":
        design = json.loads(Path(__file__).with_name("determinism-design.json").read_bytes())
        for case in design:
            if case["interpreter"] != args.interpreter:
                continue
            alternate = ROOT / ".s0" / ("unicode-\u00e9\u7f51" if case["path"] == "unicode" else "long-" + "x" * 160 if case["path"] == "long" else "short")
            shutil.copytree(input_root, alternate, copy_function=os.link)
            mapped = alternate
            aliased = os.name == "nt" and case["drive"] == "alias"
            try:
                if aliased:
                    subprocess.run(["subst.exe", "Z:", str(alternate)], check=True)
                    mapped = Path("Z:/")
                row = measure(mapped, args.raw / f"case-{case['id']}", args.runtime, 300,
                              workers=case["workers"], recycle=case["recycle"],
                              container=platform.system() == "Linux" and case["container"],
                              cap=2**31 if case["capped"] else 0,
                              environment={"PYTHONHASHSEED": case["seed"], "TZ": case["tz"], "LANG": case["lang"], "LC_ALL": case["lang"]},
                              interpreter=args.interpreter)
                row["design"] = case
                rows.append(row)
            finally:
                if aliased:
                    subprocess.run(["subst.exe", "Z:", "/D"], check=True)
                shutil.rmtree(alternate)
    elif args.mode == "stability":
        recycle = None if args.recycle == "none" else 3
        for index in range(args.count):
            row = measure(input_root, args.raw / f"run-{index + 1}", args.runtime, 300, recycle=recycle,
                          container=platform.system() == "Linux")
            rows.append(row)
            if row["status"] != "ok":
                break
    else:
        for index, (fault, cancel) in enumerate((("none", False), ("kill-once", False), ("kill-twice", False), ("none", True), ("memory", False), ("pack", False))):
            rows.append(measure(input_root, args.raw / f"fault-{index}-{fault}", args.runtime, 300,
                                container=platform.system() == "Linux", fault=fault, cancel_half=cancel))
    digests = [r.get("manifest_sha256") for r in rows if r["status"] == "ok"]
    all_ok = all(r["status"] == "ok" for r in rows)
    assessment = {"schema": 1, "mode": args.mode, "rows": rows,
                  "identical_successful_manifests": bool(digests) and len(set(digests)) == 1,
                  "status": "not_verified", "missing": []}
    if args.mode == "determinism":
        assessment["missing"] = ["PYTHONHASHSEED is ignored under required -I; fixed-seed axis unresolved", "other-interpreter/OS artifacts must be compared by supervisor"]
        assessment["observed"] = "pass" if all_ok and len(set(digests)) == 1 else "failed"
    elif args.mode == "stability":
        times = [r["wall_s"] for r in rows]
        cv = statistics.pstdev(times) / statistics.mean(times)
        assessment["wall_cv"] = cv
        assessment["status"] = "pass" if all_ok and len(rows) == 20 and cv <= 0.1 and len(set(digests)) == 1 else "failed"
        assessment["missing"] = ["per-worker first-task-plateau memory growth decision requires review of USS traces"]
    else:
        expected = ["ok", "ok", "failed", "failed", "failed", "ok"]
        statuses = [r["status"] for r in rows]
        matching_retry = len(rows) > 1 and rows[0].get("manifest_sha256") == rows[1].get("manifest_sha256")
        clean_abort = all(r.get("prior_intact") and not r.get("result_exists") and not r.get("pending_directories") for r in rows[2:5])
        assessment["single_retry_identical"] = matching_retry
        assessment["clean_abort"] = clean_abort
        assessment["status"] = "pass" if statuses == expected and matching_retry and clean_abort else "failed"
    (args.raw / "assessment.json").write_bytes(canonical(assessment))
    hashes = [f"{digest(path.read_bytes())}  {path.relative_to(args.raw).as_posix()}\n" for path in sorted(args.raw.rglob("*")) if path.is_file()]
    (args.raw / "ALL-RAW.sha256").write_text("".join(hashes), encoding="ascii")
    sys.exit(0 if assessment.get("observed", assessment["status"]) == "pass" else 1)


if __name__ == "__main__":
    main()

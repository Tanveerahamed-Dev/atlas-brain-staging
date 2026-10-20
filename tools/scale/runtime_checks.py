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


def manual_probe(runtime, seed):
    clean_env = {"PYTHONHASHSEED": seed}
    if os.name == "nt":
        for key in ("SystemRoot", "WINDIR", "TEMP", "TMP"):
            if key in os.environ:
                clean_env[key] = os.environ[key]
    flags = ["-P", "-s", "-B", "-X", "utf8=1", "-X", "warn_default_encoding", "-W", "error::EncodingWarning"]
    code = "import json,os,sys;print(json.dumps({'flags':list(sys.flags),'no_user_site':sys.flags.no_user_site,'safe_path':sys.flags.safe_path,'hash_randomization':sys.flags.hash_randomization,'seed':os.environ.get('PYTHONHASHSEED'),'hash':hash('atlas-brain-fixed-seed'),'environment_keys':sorted(os.environ)}))"
    witness = json.loads(subprocess.check_output([str(runtime.resolve())] + flags + ["-c", code], env=clean_env, encoding="utf-8"))
    if witness["no_user_site"] != 1 or not witness["safe_path"] or witness["seed"] != seed or witness["hash_randomization"] != (0 if seed == "0" else 1):
        raise ValueError("manual_seed_reference_failed")
    return {"seed": seed, "expected_hash": witness["hash"], "environment": clean_env}, witness


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
    rows, manual_rows, witnesses, manual_negative = [], [], [], None
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
        for seed in ("0", "4242"):
            profile, witness = manual_probe(args.runtime, seed)
            witnesses.append(witness)
            (args.raw / f"manual-reference-{seed}.json").write_bytes(canonical(witness))
            row = measure(input_root, args.raw / f"manual-seed-{seed}", args.runtime, 300,
                          container=False, cap=2**31 if os.name == "nt" else 0, manual=profile)
            manual_rows.append(row)
            if seed == "0":
                planted = dict(profile, expected_hash=profile["expected_hash"] + 1)
                manual_negative = measure(input_root, args.raw / "manual-wrong-hash", args.runtime, 300,
                                          container=False, cap=2**31 if os.name == "nt" else 0, manual=planted)
    elif args.mode == "stability":
        recycle = None if args.recycle == "none" else 3
        for index in range(args.count):
            row = measure(input_root, args.raw / f"run-{index + 1}", args.runtime, 300, recycle=recycle,
                          container=platform.system() == "Linux")
            rows.append(row)
            if row["status"] != "ok":
                break
    else:
        for index, (fault, cancel) in enumerate((("none", False), ("kill-once", False), ("kill-twice", False), ("none", True), ("memory", False), ("pack", False), ("pack", False), ("import-probe", False), ("swallow-probe", False))):
            rows.append(measure(input_root, args.raw / f"fault-{index}-{fault}", args.runtime, 300,
                                container=platform.system() == "Linux", fault=fault, cancel_half=cancel,
                                keep_result=index == 0, prior=None if index == 0 else args.raw / "fault-0-none" / "result"))
    digests = [r.get("manifest_sha256") for r in rows if r["status"] == "ok"]
    all_ok = all(r["status"] == "ok" for r in rows)
    assessment = {"schema": 1, "mode": args.mode, "rows": rows,
                  "identical_successful_manifests": bool(digests) and len(set(digests)) == 1,
                  "status": "not_verified", "missing": []}
    if args.mode == "determinism":
        manual_digests = [r.get("manifest_sha256") for r in manual_rows]
        refused = manual_negative is not None and manual_negative["status"] == "failed" and not manual_negative.get("result_exists") and manual_negative.get("prior_intact")
        manual_pass = len(manual_rows) == 2 and all(r["status"] == "ok" for r in manual_rows) and len(set(digests + manual_digests)) == 1 and len({w["hash"] for w in witnesses}) == 2 and refused
        assessment["manual_fixed_seed"] = {"label": "fixed-seed probes under equivalent manual isolation, not -I", "rows": manual_rows, "witnesses": witnesses, "wrong_hash_witness": manual_negative, "status": "pass" if manual_pass else "failed"}
        assessment["plan_correction"] = "-I ignores PYTHONHASHSEED. Owner-directed separate -P -s -B probes exercise 0 and 4242 with a scrubbed environment; all isolated acceptance rows retained."
        assessment["missing"] = ["other-interpreter/OS artifacts must be compared by supervisor"]
        assessment["observed"] = "pass" if all_ok and len(set(digests)) == 1 and manual_pass else "failed"
    elif args.mode == "stability":
        times = [r["wall_s"] for r in rows]
        cv = statistics.pstdev(times) / statistics.mean(times)
        assessment["wall_cv"] = cv
        assessment["status"] = "pass" if all_ok and len(rows) == 20 and cv <= 0.1 and len(set(digests)) == 1 else "failed"
        assessment["missing"] = ["per-worker first-task-plateau memory growth decision requires review of USS traces"]
    else:
        expected = ["ok", "ok", "failed", "failed", "failed", "ok", "ok", "failed", "failed"]
        statuses = [r["status"] for r in rows]
        matching_retry = len(rows) > 1 and rows[0].get("manifest_sha256") == rows[1].get("manifest_sha256")
        clean_abort = all(r.get("prior_intact") and not r.get("result_exists") and not r.get("pending_directories") for r in rows[2:5])
        assessment["single_retry_identical"] = matching_retry
        assessment["clean_abort"] = clean_abort
        pack_identical = len(rows) == 9 and rows[5].get("manifest_sha256") == rows[6].get("manifest_sha256")
        egress_closed = len(rows) == 9 and rows[7].get("engine_failure") == "EgressDenied" and rows[8].get("engine_code") == "egress_violation" and all(r.get("prior_intact") and not r.get("result_exists") for r in rows[7:9])
        assessment["pack_exception_identical"] = pack_identical
        assessment["egress_fail_closed"] = egress_closed
        assessment["status"] = "pass" if statuses == expected and matching_retry and clean_abort and pack_identical and egress_closed else "failed"
    (args.raw / "assessment.json").write_bytes(canonical(assessment))
    hashes = [f"{digest(path.read_bytes())}  {path.relative_to(args.raw).as_posix()}\n" for path in sorted(args.raw.rglob("*")) if path.is_file()]
    (args.raw / "ALL-RAW.sha256").write_text("".join(hashes), encoding="ascii")
    sys.exit(0 if assessment.get("observed", assessment["status"]) == "pass" else 1)


if __name__ == "__main__":
    main()

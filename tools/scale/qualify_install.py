"""Plant unowned and tampered dev hooks; prove preflight refuses before execution."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.subject / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    purelib = Path(subprocess.check_output([str(runtime), "-I", "-S", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"], encoding="utf-8").strip()).resolve()
    receipt = json.loads((args.raw / "dev.json").read_bytes())
    existing = next(row for row in receipt["hooks"] if row["owner"].lower() == "coverage" and row["class"] == "executable")
    owned = (purelib / existing["path"]).resolve()
    if not owned.is_relative_to(purelib):
        raise ValueError("owned_hook_outside_qualification_environment")
    original = owned.read_bytes()
    unowned = purelib / "s0_unowned_guard_probe.pth"
    if unowned.exists():
        raise ValueError("refuse_existing_probe")
    rows = []
    for label, path, expected in (("unowned", unowned, "startup_hook_ownership"),
                                  ("tampered-owned", owned, "startup_hook_record_digest")):
        marker = (args.raw / (label + "-executed")).resolve()
        body = "import os; fd = os.open(" + repr(str(marker)) + ", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 384); os.write(fd, b'os_only'); os.close(fd)\n"
        try:
            path.write_text(body, encoding="utf-8")
            command = [sys.executable, str(Path(__file__).with_name("locked_install.py")), "--subject", str(args.subject),
                       "--profile", "dev", "--out", str(args.raw / (label + "-unexpected.json"))]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (args.raw / (label + "-refusal.log")).write_bytes(result.stdout)
            if result.returncode == 0 or marker.exists() or expected not in result.stdout.decode("utf-8"):
                raise ValueError("startup_preflight_did_not_refuse_before_execution:" + label)
            subprocess.run([str(runtime), "-I", "-c", "pass"], check=True)
            if not marker.exists():
                raise ValueError("planted_hook_positive_witness_missing")
            rows.append({"case": label, "refused": True, "no_execution_before_refusal": True,
                         "positive_without_census_executed": True, "exit": result.returncode})
        finally:
            if path == owned:
                owned.write_bytes(original)
            else:
                path.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
    if owned.read_bytes() != original:
        raise ValueError("owned_hook_not_restored")
    (args.raw / "startup-ownership-witness.json").write_text(json.dumps({"schema": 1, "status": "pass", "cases": rows, "original_hook_restored": True}, sort_keys=True) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()

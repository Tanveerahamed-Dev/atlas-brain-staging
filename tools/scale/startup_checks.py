"""Hosted planting after a clean reference, before coordinator/worker startup."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.scale.measure import FLAGS, shape
from tools.scale.workload import canonical, digest, generate

WITNESSES = {
    "pth-connect": {"planted.pth": "import startup_planted; startup_planted.connect()\n"},
    "pth-loaded-os": {"planted.pth": "import os; os.environ['S0_ALREADY_LOADED_OS'] = 'executed'\n"},
    "start-connect": {"planted.start": "startup_planted:connect\n"},
    "sitecustomize": {"sitecustomize.py": "from startup_planted import connect\nconnect()\n"},
    "start-pth-pair": {"planted.start": "startup_planted:connect\n", "planted.pth": "import os; os.environ['S0_ALREADY_LOADED_OS'] = 'executed'\n"},
}
HELPER = """
def connect():
    import os, pathlib, socket
    pathlib.Path(os.environ['S0_STARTUP_EXECUTED']).write_text('executed', encoding='ascii')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.05)
            connection.connect(('192.0.2.1', 9))
    except OSError:
        pass
"""


def await_marker(process, marker):
    until = time.monotonic() + 120
    while not marker.exists():
        if process.poll() is not None:
            raise ValueError("parent_refused_before_planting")
        if time.monotonic() > until:
            raise TimeoutError("startup_plant_watchdog")
        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    args = parser.parse_args()
    args.runtime = args.runtime.absolute()
    args.raw.mkdir(parents=True)
    sites = json.loads(subprocess.check_output([str(args.runtime), "-I", "-S", "-c",
                       "import json,site;print(json.dumps(site.getsitepackages()))"], encoding="utf-8"))
    site = next(Path(p) for p in sites if Path(p).is_dir())
    source = ROOT / ".s0" / "input-100"
    generate(source, 100, False)
    records = []
    for name, files in WITNESSES.items():
        for phase in ("prestart", "coordinator", "worker"):
            case = args.raw / (name + "-" + phase)
            case.mkdir()
            control = case / "control"
            control.mkdir()
            out, receipt = case / "result", case / "engine.json"
            marker = case / "startup-executed"
            env = dict(os.environ, S0_STARTUP_EXECUTED=str(marker.resolve()))
            command = [str(args.runtime)] + FLAGS + [str(ROOT / "spike" / "bootstrap.py"),
                       "--root", str(source), "--out", str(out), "--receipt", str(receipt), "--control", str(control)]
            process = None
            with (case / "console.log").open("wb") as console:
                try:
                    if phase == "worker":
                        process = subprocess.Popen(command + ["--pause-before-workers"], env=env, stdout=console, stderr=subprocess.STDOUT)
                        await_marker(process, control / "before-workers.ready")
                    for filename, body in dict(files, **{"startup_planted.py": HELPER}).items():
                        path = site / filename
                        if path.exists():
                            raise ValueError("refuse_overwriting_existing_startup_file")
                        path.write_text(body, encoding="utf-8")
                    if phase == "prestart":
                        process = subprocess.Popen([str(args.runtime), "-I", "-S", str(ROOT / "tools" / "scale" / "prepare.py")],
                                                   env=env, stdout=console, stderr=subprocess.STDOUT)
                    elif phase == "coordinator":
                        process = subprocess.Popen(command, env=env, stdout=console, stderr=subprocess.STDOUT)
                    else:
                        (control / "before-workers.release").write_text("release\n", encoding="ascii")
                    code = process.wait(timeout=120)
                finally:
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait()
                    for filename in list(files) + ["startup_planted.py"]:
                        (site / filename).unlink(missing_ok=True)
                    # Hook bytecode must not survive between planted trials.
                    for cache in (site / "__pycache__").glob("*"):
                        if cache.name.startswith(("startup_planted.", "sitecustomize.")):
                            cache.unlink()
            log = (case / "console.log").read_text(encoding="utf-8")
            refusal = "startup_code_unadmitted" in log or "startup_module_baseline" in log
            if code == 0 or not refusal or out.exists() or list(case.glob(".pending-*")):
                raise ValueError("startup_hook_not_refused:" + name + ":" + phase)
            if phase == "prestart" and marker.exists():
                raise ValueError("prestart_census_executed_hook")
            expected_execution = name in ("pth-connect", "sitecustomize") or sys.version_info[:2] >= (3, 15) and name in ("start-connect", "start-pth-pair")
            if phase != "prestart" and expected_execution and not marker.exists():
                raise ValueError("startup_executable_positive_control_missing:" + name)
            records.append({"witness": name, "phase": phase, "exit": code, "refused": refusal,
                            "hook_ran_before_refusal": marker.exists(), "no_result": True})
    case = args.raw / "unlisted-import"
    case.mkdir()
    unlisted = site / "startup_unlisted_probe.py"
    sentinel = case / "module-body-ran"
    if unlisted.exists():
        raise ValueError("refuse_existing_unlisted_probe")
    try:
        unlisted.write_text("from pathlib import Path\nPath(" + repr(str(sentinel.resolve())) + ").write_text('ran', encoding='ascii')\n", encoding="utf-8")
        command = [str(args.runtime)] + FLAGS + [str(ROOT / "spike" / "bootstrap.py"),
                   "--root", str(source), "--out", str(case / "result"), "--receipt", str(case / "engine.json"),
                   "--control", str(case / "control"), "--fault", "admission-probe"]
        with (case / "console.log").open("wb") as log:
            result = subprocess.run(command, timeout=120, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode == 0 or sentinel.exists() or (case / "result").exists() or "import_unadmitted:startup_unlisted_probe" not in (case / "console.log").read_text(encoding="utf-8"):
            raise ValueError("unlisted_import_not_refused_before_execution")
        records.append({"witness": "unlisted-import", "phase": "worker", "exit": result.returncode,
                        "refused": True, "module_body_ran": False, "no_result": True})
    finally:
        unlisted.unlink()
    # Clean opt-in -S option: same runtime input, no site processing at all.
    hashes = []
    for no_site in (False, True):
        case = args.raw / ("clean-no-site" if no_site else "clean-site")
        case.mkdir()
        command = [str(args.runtime)] + FLAGS + (["-S"] if no_site else []) + [str(ROOT / "spike" / "bootstrap.py"),
                   "--root", str(source), "--out", str(case / "result"), "--receipt", str(case / "engine.json"), "--control", str(case / "control")]
        with (case / "console.log").open("wb") as log:
            subprocess.run(command, check=True, timeout=120, stdout=log, stderr=subprocess.STDOUT)
        hashes.append(digest((case / "result" / "MANIFEST.sha256").read_bytes()))
        shutil.rmtree(case / "result")
    if hashes[0] != hashes[1]:
        raise ValueError("no_site_option_bytes_differ")
    receipt = {"schema": 1, "status": "pass", "runner": shape(), "cases": records,
               "optional_no_site_bytes_equal": True, "manifests": hashes,
               "scope": "runtime clean references, five planted hook classes across prestart/coordinator/worker; host detects and refuses startup code after execution"}
    (args.raw / "startup.json").write_bytes(canonical(receipt))
    paths = [p for p in args.raw.rglob("*") if p.is_file()]
    (args.raw / "RAW.sha256").write_text("".join(f"{digest(p.read_bytes())}  {p.relative_to(args.raw).as_posix()}\n" for p in sorted(paths)), encoding="ascii")


if __name__ == "__main__":
    main()

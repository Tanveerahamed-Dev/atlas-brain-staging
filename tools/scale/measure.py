"""Hosted-only 20 Hz whole-tree USS sampling, hard caps, watchdog and receipts."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import time
import uuid

import psutil  # Harness dependency only. Never imported by an engine process.

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.scale.workload import canonical, digest, generate, verify

FLAGS = ["-I", "-X", "utf8=1", "-X", "warn_default_encoding", "-W", "error::EncodingWarning"]
PREPARED_IMAGES = set()


def command(*args):
    return subprocess.check_output(list(args), encoding="utf-8").strip()


def shape():
    return {"cpu_count": os.cpu_count(), "process_cpu_count": os.process_cpu_count(),
            "memory_bytes": psutil.virtual_memory().total, "os": platform.system(),
            "platform": platform.platform(), "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"), "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"), "python": platform.python_version(),
            "head": command("git", "rev-parse", "HEAD")}


def cgroup_files(pid):
    try:
        line = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").strip()
        relative = next(s.split(":", 2)[2] for s in line.splitlines() if s.startswith("0::"))
        return Path("/sys/fs/cgroup") / relative.lstrip("/")
    except (OSError, StopIteration):
        return None


def cg_read(folder):
    if folder is None:
        return {}
    result = {}
    for name in ("memory.peak", "memory.max", "memory.swap.max"):
        try:
            result[name] = folder.joinpath(name).read_text(encoding="ascii").strip()
        except OSError:
            pass
    for name in ("memory.stat", "memory.events"):
        try:
            result[name] = {parts[0]: int(parts[1]) for parts in (s.split() for s in folder.joinpath(name).read_text(encoding="ascii").splitlines())}
        except OSError:
            pass
    return result


def kill_tree(processes):
    for process in reversed(list(processes.values())):
        try:
            if process.is_running():
                process.kill()
        except psutil.NoSuchProcess:
            pass


def sample_memory(process):
    try:
        return process.memory_full_info(), None
    except psutil.AccessDenied:
        # Windows can deny VM queries during process teardown. Require actual exit
        # within one sampling period; a still-live denial remains a failed measure.
        try:
            process.wait(timeout=0.05)
        except (psutil.TimeoutExpired, psutil.AccessDenied):
            raise psutil.AccessDenied(process.pid)
        return None, "confirmed_exit_after_access_denial"


def result_snapshot(directory):
    if not directory.is_dir():
        raise FileNotFoundError("prior_result_missing")
    return {p.relative_to(directory).as_posix(): digest(p.read_bytes()) for p in sorted(directory.rglob("*")) if p.is_file()}


def measure(input_root, output_root, runtime, size, dense=False, workers=4, recycle=None,
            container=False, cap=2**31, fault="none", cancel_half=False, environment=None, interpreter="3.14.8", manual=None, prior=None, keep_result=False):
    output_root.mkdir(parents=True, exist_ok=False)
    control = output_root / "control"
    control.mkdir()
    result = output_root / "result"
    engine_receipt = output_root / "engine.json"
    # A prior result is outside the attempted output; every failure must preserve it.
    prior_basis = "earlier successful analysis result" if prior else "synthetic prior result witness"
    if prior is None:
        prior = output_root / "prior-result"
        prior.mkdir()
        prior_body = b'{"prior":"intact"}\n'
        (prior / "estate.json").write_bytes(prior_body)
        (prior / "MANIFEST.sha256").write_text(digest(prior_body) + "  estate.json\n", encoding="ascii")
    prior_hash = result_snapshot(prior)
    metadata = {"schema": 1, "runner": shape(), "size": size, "dense": dense,
                "os": platform.system(), "cap_bytes": cap, "container": container,
                "fault": fault, "workers_requested": workers, "recycle": recycle,
                "manual_isolation": manual is not None,
                "prior_basis": prior_basis, "prior_files": len(prior_hash),
                "status": "starting", "cancel_half": cancel_half, "sample_hz": 20}
    samples, known, errors, io_errors, exit_races = [], {}, [], [], []
    job, container_id, cg = None, None, None
    logfile = (output_root / "console.log").open("wb")
    started = time.monotonic()
    process = None
    sampled_cg, job_peak = {}, None
    try:
        if container:
            if interpreter not in PREPARED_IMAGES:
                subprocess.run(["docker", "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                                "--mount", f"type=bind,src={ROOT},dst=/repo,readonly",
                                "--mount", f"type=bind,src={ROOT / '.s0'},dst=/repo/.s0",
                                "--workdir", "/repo", f"python:{interpreter}-slim", "python", "-I", "-S",
                                "tools/scale/prepare.py", "--references-only"], check=True)
                PREPARED_IMAGES.add(interpreter)
            container_input = "/inputs/" + input_root.name
            arguments = ["python"] + FLAGS + ["/repo/spike/bootstrap.py", "--root", container_input, "--out", "/run/result", "--receipt", "/run/engine.json", "--control", "/run/control", "--workers", str(workers), "--fault", fault]
            if recycle:
                arguments += ["--recycle", str(recycle)]
            if cancel_half:
                arguments += ["--pause-at-half"]
            arguments = ["python"] + FLAGS + ["/repo/tools/scale/container_supervisor.py", "/run/cgroup-final.json", "--"] + arguments
            create = ["docker", "create", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                      "--mount", f"type=bind,src={ROOT},dst=/repo,readonly",
                      "--mount", f"type=bind,src={input_root.resolve()},dst={container_input},readonly",
                      "--mount", f"type=bind,src={output_root.resolve()},dst=/run", "--workdir", "/repo"]
            if cap:
                create += ["--memory", str(cap), "--memory-swap", str(cap)]
            for key, value in (environment or {}).items():
                create += ["--env", f"{key}={value}"]
            container_id = command(*(create + [f"python:{interpreter}-slim"] + arguments))
            started = time.monotonic()
            process = subprocess.Popen(["docker", "start", "--attach", container_id], stdout=logfile, stderr=subprocess.STDOUT)
            pid = 0
            for _ in range(100):
                pid = int(command("docker", "inspect", "--format", "{{.State.Pid}}", container_id))
                if pid or process.poll() is not None:
                    break
                time.sleep(0.05)
            if not pid:
                raise RuntimeError("container_pid_unavailable")
            root_process = psutil.Process(pid)
            cg = cgroup_files(pid)
        else:
            launch_flags = ["-P", "-s", "-B"] + FLAGS[1:] if manual else FLAGS
            arguments = [str(runtime.resolve())] + launch_flags + [str(ROOT / "spike" / "bootstrap.py"), "--root", str(input_root.absolute()), "--out", str(result.resolve()), "--receipt", str(engine_receipt.resolve()), "--control", str(control.resolve()), "--workers", str(workers), "--fault", fault]
            if manual:
                arguments += ["--manual-isolation", "--expected-seed", manual["seed"], "--expected-hash", str(manual["expected_hash"])]
            if recycle:
                arguments += ["--recycle", str(recycle)]
            if cancel_half:
                arguments += ["--pause-at-half"]
            options = {"env": manual["environment"] if manual else dict(os.environ, **(environment or {})), "stdout": logfile, "stderr": subprocess.STDOUT}
            if os.name == "nt":
                from tools.scale.windows_job import Job
                job = Job(cap)
                options["creationflags"] = 0x00000004 | subprocess.CREATE_NEW_PROCESS_GROUP  # CREATE_SUSPENDED
            elif cap:
                raise RuntimeError("linux_cap_requires_container")
            started = time.monotonic()
            process = subprocess.Popen(arguments, **options)
            root_process = psutil.Process(process.pid)
            if job:
                job.assign_and_resume(process)
        last_progress, last_bytes, next_sample = time.monotonic(), None, time.monotonic()
        cancel_sent = False
        while process.poll() is None:
            now = time.monotonic()
            tree_uss, tree_rss, cpu_s, io_written = 0, 0, 0, 0
            try:
                current = [root_process] + root_process.children(recursive=True)
            except psutil.NoSuchProcess:
                current = []
            pid_rows = []
            for member in current:
                try:
                    known[(member.pid, member.create_time())] = member
                    memory, race = sample_memory(member)
                    if race:
                        exit_races.append({"pid": member.pid, "t_s": now - started, "kind": race})
                        continue
                    tree_uss += memory.uss
                    tree_rss += memory.rss
                    member_cpu = None
                    try:
                        usage = member.cpu_times()
                        member_cpu = usage.user + usage.system
                        cpu_s += member_cpu
                        io_written += member.io_counters().write_bytes
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        io_errors.append({"pid": member.pid, "t_s": now - started, "kind": "cpu_or_io_unavailable"})
                    pid_rows.append([member.pid, memory.uss, memory.rss, member_cpu])
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    errors.append("process_memory_access_denied")
            group = cg_read(cg)
            if group:
                sampled_cg = group
            samples.append({"t_s": now - started, "uss": tree_uss, "rss": tree_rss, "cpu_s": cpu_s, "written": io_written,
                            "anon": group.get("memory.stat", {}).get("anon"), "pids": pid_rows})
            progress_files = [control / "progress.json", control / "retry-progress.json"]
            progress = b"".join(p.read_bytes() for p in progress_files if p.exists())
            if progress != last_bytes:
                last_bytes, last_progress = progress, now
            completed = 0
            try:
                completed = json.loads((control / "progress.json").read_bytes())["completed"]
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            if cancel_half and completed >= size // 2 and not cancel_sent:
                if container:
                    command("docker", "kill", "--signal", "SIGTERM", container_id)
                elif os.name == "nt":
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.send_signal(signal.SIGTERM)
                cancel_sent = True
            if now - last_progress > 120:
                metadata["status"] = "watchdog"
                kill_tree(known)
                if container_id:
                    command("docker", "kill", container_id)
                process.kill()
                break
            next_sample += 0.05
            time.sleep(max(0, next_sample - time.monotonic()))
        exit_code = process.wait(timeout=15)
        wall = time.monotonic() - started
        if job:
            job_peak = job.peak()
        metadata["exit_code"] = exit_code
        metadata["wall_s"] = wall
        metadata["status"] = "ok" if exit_code == 0 and metadata["status"] != "watchdog" else metadata["status"] if metadata["status"] == "watchdog" else "failed"
        # S0-d's post-exit orphan observation is outside timed wall.
        time.sleep(5)
        orphans = []
        for key, member in known.items():
            try:
                if member.is_running() and member.status() != psutil.STATUS_ZOMBIE:
                    orphans.append(member.pid)
            except psutil.NoSuchProcess:
                pass
        metadata["orphans_after_5s"] = sorted(orphans)
        metadata["job_active_after_5s"] = job.active() if job else None
        if orphans or metadata["job_active_after_5s"]:
            metadata["status"] = "orphan"
            kill_tree(known)
        if container_id:
            state = json.loads(command("docker", "inspect", container_id))[0]
            metadata["docker_state"] = {key: state["State"].get(key) for key in ("ExitCode", "OOMKilled", "Error")}
            metadata["cap_verified"] = state["HostConfig"]["Memory"] == cap and state["HostConfig"]["MemorySwap"] == cap
        else:
            metadata["cap_verified"] = job is not None and cap > 0
        if engine_receipt.exists():
            engine = json.loads(engine_receipt.read_bytes())
            metadata["engine_status"] = engine["status"]
            metadata["engine_failure"] = engine.get("failure")
            metadata["engine_code"] = engine.get("code")
            for key in ("stages", "manifest_sha256", "facts", "task_bytes", "result_bytes", "result_payload_bytes", "serialization_probe_ns", "pickling_share"):
                metadata[key] = engine.get(key)
            if engine["status"] != "ok" and metadata["status"] == "ok":
                metadata["status"] = "failed"
        final_cgroup = output_root / "cgroup-final.json"
        if container and final_cgroup.exists():
            metadata["cgroup_final"] = json.loads(final_cgroup.read_bytes())
            metadata["cgroup_peak"] = metadata["cgroup_final"]["memory.peak"]
        elif container and metadata["status"] == "ok":
            metadata["status"] = "measurement_incomplete"
        metadata["result_exists"] = result.exists()
        metadata["prior_intact"] = result_snapshot(prior) == prior_hash
        metadata["pending_directories"] = [p.name for p in output_root.glob(".pending-*")]
        if metadata["status"] == "ok" and not result.exists():
            metadata["status"] = "publication_failed"
        if not metadata["prior_intact"] or (metadata["status"] != "ok" and (result.exists() or metadata["pending_directories"])):
            metadata["status"] = "partial_publication"
    except BaseException as exc:
        metadata.update(status="harness_error", failure=type(exc).__name__, detail=str(exc)[:160], wall_s=time.monotonic() - started)
        kill_tree(known)
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=15)
    finally:
        logfile.close()
        if job:
            job.close()
        if container_id:
            subprocess.run(["docker", "rm", "-f", container_id], check=False, stdout=subprocess.DEVNULL)
        metadata.update({"samples": len(samples), "sampling_errors": sorted(set(errors)), "io_sampling_errors": io_errors, "confirmed_exit_races": exit_races, "cgroup_last": sampled_cg,
                         "peak_job_commit": job_peak, "peak_tree_uss": max((s["uss"] for s in samples), default=0),
                         "median_tree_uss": statistics.median([s["uss"] for s in samples]) if samples else 0,
                         "max_tree_rss": max((s["rss"] for s in samples), default=0),
                         "peak_anon": max((s["anon"] or 0 for s in samples), default=0),
                         "sample_intervals_max_s": max((b["t_s"] - a["t_s"] for a, b in zip(samples, samples[1:])), default=0),
                         "cgroup_peak_scope": "final after engine exit when cgroup_final exists; otherwise last available sample"})
        if errors and metadata["status"] == "ok":
            metadata["status"] = "measurement_incomplete"
        (output_root / "samples.jsonl").write_bytes(b"".join(canonical(s) for s in samples))
        (output_root / "measurement.json").write_bytes(canonical(metadata))
        # Retain compact operational evidence, engine receipt and canonical manifest.
        # The input and large per-device outputs are reproducible and not uploaded.
        if result.exists():
            shutil.copyfile(result / "MANIFEST.sha256", output_root / "MANIFEST.sha256")
            shutil.copyfile(result / "estate.json", output_root / "estate.json")
            if not keep_result:
                shutil.rmtree(result)
        hashes = [f"{digest(path.read_bytes())}  {path.relative_to(output_root).as_posix()}\n" for path in sorted(output_root.rglob("*")) if path.is_file()]
        (output_root / "RAW.sha256").write_text("".join(hashes), encoding="ascii")
    print(json.dumps({k: metadata.get(k) for k in ("status", "size", "wall_s", "peak_tree_uss", "peak_job_commit", "cap_verified")}, sort_keys=True), flush=True)
    return metadata


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[100, 300])
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--dense", action="store_true")
    parser.add_argument("--host", action="store_true")
    args = parser.parse_args()
    failed = False
    for size in args.sizes:
        input_root = ROOT / ".s0" / f"input-{size}{'-dense' if args.dense else ''}"
        if not input_root.exists():
            generate(input_root, size, args.dense)
        else:
            verify(input_root)
        for run in range(args.repetitions):
            out = args.raw / f"wl1-{size}{'-dense' if args.dense else ''}-{run + 1}"
            row = measure(input_root, out, args.runtime, size, args.dense,
                          container=platform.system() == "Linux" and not args.host,
                          cap=(4 if args.dense else 2) * 2**30 if not args.host else 0)
            if row["status"] != "ok":
                failed = True
                break
        if failed:
            break
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

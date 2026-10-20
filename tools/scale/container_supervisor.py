"""Keep the cgroup alive until its final engine-tree peak has been read."""
import json
from pathlib import Path
import signal
import subprocess
import sys


def collect(folder):
    result = {}
    for name in ("memory.peak", "memory.max", "memory.swap.max"):
        result[name] = int((folder / name).read_text(encoding="ascii").strip())
    for name in ("memory.events", "memory.stat"):
        result[name] = {key: int(value) for key, value in (line.split() for line in (folder / name).read_text(encoding="ascii").splitlines())}
    return result


def main():
    target = Path(sys.argv[1])
    argv = sys.argv[2:]
    if argv[0] != "--":
        raise ValueError("supervisor_arguments")
    child = subprocess.Popen(argv[1:])
    def forward(number, frame):
        child.send_signal(number)
    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    code = child.wait()
    record = collect(Path("/sys/fs/cgroup"))
    record["child_exit_code"] = code
    record["scope"] = "after engine and workers exit; includes supervisor overhead"
    target.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="ascii")
    sys.exit(code if code >= 0 else 128 - code)


if __name__ == "__main__":
    main()

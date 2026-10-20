"""Linux L-c witness: a reachable runner-local listener, then ENETUNREACH."""
import argparse
import errno
import hashlib
import json
from pathlib import Path
import subprocess
import uuid


def invoke(*args):
    return subprocess.check_output(list(args), encoding="utf-8").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    name = "s0-" + uuid.uuid4().hex[:12]
    image = "python:3.14.8-slim"
    listener = None
    record = {"schema": 1, "status": "failed"}
    try:
        invoke("docker", "network", "create", "--subnet", "192.0.2.0/24", name)
        listener = invoke("docker", "run", "--detach", "--network", name, "--ip", "192.0.2.2", image,
                          "python", "-I", "-S", "-c", "import socket,time;s=socket.socket();s.bind(('192.0.2.2',9000));s.listen();time.sleep(60)")
        code = """import errno,json,socket,time
result={'interfaces':sorted(name for _,name in socket.if_nameindex())}
s=socket.socket();s.settimeout(2)
try:
 s.connect(('192.0.2.2',9000));result['connected']=True;result['errno']=None
except OSError as error:
 result['connected']=False;result['errno']=error.errno
finally:
 s.close()
print(json.dumps(result,sort_keys=True))
"""
        positive = json.loads(invoke("docker", "run", "--rm", "--network", name, image, "python", "-I", "-S", "-c", code))
        confined = json.loads(invoke("docker", "run", "--rm", "--network", "none", image, "python", "-I", "-S", "-c", code))
        record.update(positive=positive, confined=confined, expected_errno=errno.ENETUNREACH,
                      status="pass" if positive["connected"] and confined["interfaces"] == ["lo"] and not confined["connected"] and confined["errno"] == errno.ENETUNREACH else "failed")
    except BaseException as exc:
        record["failure"] = type(exc).__name__
    finally:
        if listener:
            subprocess.run(["docker", "rm", "-f", listener], check=False, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", name], check=False, stdout=subprocess.DEVNULL)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(record, sort_keys=True) + "\n").encode("ascii")
        args.out.write_bytes(raw)
        args.out.with_suffix(".sha256").write_text(hashlib.sha256(raw).hexdigest() + "  " + args.out.name + "\n", encoding="ascii")
    raise SystemExit(0 if record["status"] == "pass" else 1)


if __name__ == "__main__":
    main()

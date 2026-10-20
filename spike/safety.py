"""Audit tripwire and code admission, independent of spike parsers."""
import hashlib
import json
import os
from pathlib import Path
import sys
import threading

VIOLATIONS = 0
CREATIONS = []
IMPORTS = set()
_INSTALLED = False
_WORKER = False
_CTYPES_READY = False
_WINDOWS_CREATION = threading.local()
_WINDOWS_WRAPPED = False
DENIED = {"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
          "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
          "urllib.Request", "http.client.connect", "ftplib.connect", "smtplib.connect", "webbrowser.open",
          "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.startfile", "ctypes.dlopen"}


class EgressDenied(BaseException):
    pass


def _creation_allowed(args):
    """Only CPython's exact spawn and resource-tracker command grammars."""
    if _WORKER:
        return False
    if os.name == "nt":
        application, command = args[:2]
        # CPython's Windows venv spawn bypasses the redirector via this exact base.
        executable = sys._base_executable if sys.executable != sys._base_executable else sys.executable
        if application is not None and os.path.normcase(application) != os.path.normcase(executable):
            return False
        # Windows quoting and numeric handles are checked, never arbitrary code.
        import re
        import shlex
        values = [v[1:-1] if v.startswith('"') and v.endswith('"') else v for v in shlex.split(command, posix=False)]
    else:
        executable_list, argv = args[:2]
        if [os.fsdecode(e) for e in executable_list] != [sys.executable]:
            return False
        values = [os.fsdecode(value) for value in argv]
        executable = sys.executable
    import subprocess
    prefix = [executable] + subprocess._args_from_interpreter_flags()
    if values[:len(prefix)] != prefix:
        return False
    import re
    tail = values[len(prefix):]
    if os.name != "nt" and len(tail) == 2 and tail[0] == "-c":
        return re.fullmatch(r"from multiprocessing.resource_tracker import main;main\(\d+\)", tail[1]) is not None
    if len(tail) == 3 and tail[0] == "-c" and tail[2] == "--multiprocessing-fork":
        grammar = r"from multiprocessing.spawn import spawn_main; spawn_main\(parent_pid=\d+, pipe_handle=\d+\)" if os.name == "nt" else r"from multiprocessing.spawn import spawn_main; spawn_main\(tracker_fd=\d+, pipe_handle=\d+\)"
        return re.fullmatch(grammar, tail[1]) is not None
    return False


def _audit(event, args):
    global VIOLATIONS
    if event == "import":
        IMPORTS.add(args[0])
    refused = event in DENIED
    if event == "socket.__new__":
        refused = args[1] != 1  # AF_UNIX only; numeric avoids importing socket in hook.
    if event in ("_posixsubprocess.fork_exec", "_winapi.CreateProcess"):
        attested = getattr(_WINDOWS_CREATION, "validated", None) if event == "_winapi.CreateProcess" else None
        if attested is not None:
            _WINDOWS_CREATION.validated = None  # One native event, same thread, same application.
            allowed = args[0] == attested[0] and not _WORKER
        else:
            allowed = _creation_allowed(args)
        CREATIONS.append({"event": event, "allowed": allowed, "grammar": "cpython-spawn-or-tracker",
                          "observed": [repr(value) for value in args[:2]],
                          "validated_command": attested[1] if attested is not None else None})
        refused = not allowed
    if refused:
        VIOLATIONS += 1
        raise EgressDenied(event)


def install(worker=False):
    global _INSTALLED, _WORKER, _WINDOWS_WRAPPED
    _WORKER = worker
    if os.name == "nt" and not _WINDOWS_WRAPPED:
        import _winapi
        original = _winapi.CreateProcess
        def guarded(application, command, process_attrs, thread_attrs, inherit, flags, env, cwd, startup):
            # 3.14.8's C audit event formats its PyObject command as wchar_t*.
            # Validate real arguments BEFORE C; an unbound native event remains refused.
            if not _creation_allowed((application, command, cwd)):
                global VIOLATIONS
                VIOLATIONS += 1
                raise EgressDenied("_winapi.CreateProcess.command")
            _WINDOWS_CREATION.validated = (application, command)
            try:
                return original(application, command, process_attrs, thread_attrs, inherit, flags, env, cwd, startup)
            finally:
                _WINDOWS_CREATION.validated = None
        _winapi.CreateProcess = guarded
        _WINDOWS_WRAPPED = True
    if not _INSTALLED:
        sys.addaudithook(_audit)
        _INSTALLED = True


def census(directories=None):
    if directories is None:
        import site
        directories = [Path(p) for p in site.getsitepackages()] + [Path(p) for p in sys.path if Path(p).is_dir()]
    rows = []
    for directory in sorted(set(directories)):
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            name = path.name.lower()
            special = name in ("sitecustomize.py", "usercustomize.py", "sitecustomize", "usercustomize", "sitecustomize.pyc", "usercustomize.pyc", "sitecustomize.pyd", "usercustomize.pyd", "sitecustomize.so", "usercustomize.so")
            if not special and not name.endswith((".pth", ".start")):
                continue
            raw = path.read_bytes() if path.is_file() else b"package"
            lines = raw.decode("utf-8-sig").splitlines()
            executable = special or (name.endswith(".start") and any(s.strip() and not s.startswith("#") for s in lines)) or (name.endswith(".pth") and any(s.startswith(("import ", "import\t")) for s in lines))
            rows.append({"name": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "class": "executable" if executable else "path_only"})
            if executable:
                raise ValueError("startup_code_unadmitted:" + path.name)
    return rows


def verify_catalogue(root, catalogue):
    for name, expected in catalogue.items():
        path = root / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("catalogue_digest")


def check_runtime_catalogue():
    root = Path(__file__).resolve().parent
    catalogue = json.loads((root / "CATALOGUE.json").read_bytes())
    actual = {p.name for p in root.glob("*.py")}
    if actual != set(catalogue):
        raise ValueError("catalogue_members")
    verify_catalogue(root, catalogue)
    return hashlib.sha256((root / "CATALOGUE.json").read_bytes()).hexdigest()


def probes():
    """Each has exactly one counted denial; nothing reaches a network."""
    import socket
    import subprocess
    import urllib.request
    methods = {
        "tcp": lambda: socket.create_connection(("192.0.2.1", 9)),
        "udp": lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"probe", ("192.0.2.1", 9)),
        "dns": lambda: socket.getaddrinfo("atlas-probe.invalid", 9),
        "url": lambda: urllib.request.urlopen("http://192.0.2.1:9"),
        "subprocess": lambda: subprocess.Popen([sys.executable, "-c", "pass"]),
        "system": lambda: os.system("echo planted-egress-probe"),
    }
    records = []
    for name, method in methods.items():
        before = VIOLATIONS
        denied = False
        try:
            method()
        except EgressDenied:
            denied = True
        records.append({"probe": name, "denied": denied, "count": VIOLATIONS - before})
    # Except Exception cannot consume the BaseException; a broad swallow is caught by count.
    before = VIOLATIONS
    try:
        try:
            socket.socket(socket.AF_INET)
        except Exception:
            pass
    except EgressDenied:
        pass
    records.append({"probe": "swallow-exception", "denied": VIOLATIONS == before + 1, "count": VIOLATIONS - before})
    return records

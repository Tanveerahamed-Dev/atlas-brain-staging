"""Queue serialization instrumentation; raw receipts stay outside canonical bytes."""
import json
from multiprocessing.reduction import ForkingPickler
from multiprocessing.util import Finalize
import os
from pathlib import Path
import threading
import time

_COUNTERS = {"dump_ns": 0, "load_ns": 0, "dump_bytes": 0, "load_bytes": 0}
_LOCK = threading.Lock()
_INSTALLED = False


def snapshot():
    with _LOCK:
        return dict(_COUNTERS, pid=os.getpid(), process_cpu_ns=time.process_time_ns())


def _flush(directory):
    (Path(directory) / f"worker-metrics-{os.getpid()}.json").write_text(json.dumps(snapshot(), sort_keys=True) + "\n", encoding="ascii")


def install(directory):
    global _INSTALLED
    if _INSTALLED:
        return
    original_dumps, original_loads = ForkingPickler.dumps, ForkingPickler.loads
    def dumps(cls, obj, protocol=None):
        start = time.perf_counter_ns()
        raw = original_dumps(obj, protocol)
        elapsed = time.perf_counter_ns() - start
        with _LOCK:
            _COUNTERS["dump_ns"] += elapsed
            _COUNTERS["dump_bytes"] += len(raw)
        return raw
    def loads(raw, *args, **kwargs):
        start = time.perf_counter_ns()
        result = original_loads(raw, *args, **kwargs)
        elapsed = time.perf_counter_ns() - start
        with _LOCK:
            _COUNTERS["load_ns"] += elapsed
            _COUNTERS["load_bytes"] += len(raw)
        return result
    ForkingPickler.dumps = classmethod(dumps)
    ForkingPickler.loads = staticmethod(loads)
    if directory is not None:
        Finalize(None, _flush, args=(directory,), exitpriority=-1)
    _INSTALLED = True

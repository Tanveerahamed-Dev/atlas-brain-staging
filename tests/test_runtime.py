"""Runtime guards have planted violations; this file does not seed S0-b."""
from pathlib import Path
import tempfile
import unittest
import os
import subprocess
import sys

from spike.safety import census, verify_catalogue


class AdmissionTests(unittest.TestCase):
    def test_creation_grammar_allows_only_real_spawn_shapes(self):
        from spike.safety import _creation_allowed
        executable = sys._base_executable if os.name == "nt" else sys.executable
        prefix = [executable] + subprocess._args_from_interpreter_flags()
        code = "from multiprocessing.spawn import spawn_main; spawn_main(" + ("parent_pid=1, pipe_handle=2)" if os.name == "nt" else "tracker_fd=1, pipe_handle=2)")
        argv = prefix + ["-c", code, "--multiprocessing-fork"]
        args = (executable, " ".join('"' + s + '"' for s in argv), None) if os.name == "nt" else ([os.fsencode(executable)], [os.fsencode(v) for v in argv], None)
        self.assertTrue(_creation_allowed(args))
        argv[-2] = "print('planted arbitrary code')"
        bad = (executable, " ".join('"' + s + '"' for s in argv), None) if os.name == "nt" else ([os.fsencode(executable)], [os.fsencode(v) for v in argv], None)
        self.assertFalse(_creation_allowed(bad))
        if os.name == "nt":
            self.assertFalse(_creation_allowed((executable, "\x01", None)))

    def test_five_startup_witnesses(self):
        witnesses = {
            "probe.pth": "import socket; socket.socket()\n",
            "loaded.pth": "import os\n",
            "probe.start": "probe:connect\n",
            "sitecustomize.py": "import os\n",
            "paired.start": "probe:connect\n",
        }
        for name, body in witnesses.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                directory = Path(root)
                (directory / name).write_text(body, encoding="utf-8")
                if name == "paired.start":
                    (directory / "paired.pth").write_text("import os\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "startup_code_unadmitted"):
                    census([directory])

    def test_path_only_file_is_recorded(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "paths.pth").write_text("../purelib\n", encoding="utf-8")
            self.assertEqual(census([Path(root)])[0]["class"], "path_only")

    def test_modified_code_refused_before_import(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / "pack.py").write_bytes(b"planted = True\n")
            with self.assertRaisesRegex(ValueError, "catalogue"):
                verify_catalogue(directory, {"pack.py": "0" * 64})


class MeasurementTests(unittest.TestCase):
    def test_final_cgroup_peak_requires_kernel_files(self):
        from tools.scale.container_supervisor import collect
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            with self.assertRaises(FileNotFoundError):
                collect(directory)
            for name, body in {"memory.peak": "4096", "memory.max": "2147483648", "memory.swap.max": "0", "memory.events": "oom_kill 0\n", "memory.stat": "anon 2048\n"}.items():
                (directory / name).write_text(body, encoding="ascii")
            self.assertEqual(collect(directory)["memory.peak"], 4096)

    def test_real_queue_pickle_roundtrip_is_measured(self):
        from multiprocessing.reduction import ForkingPickler
        from spike import metrics
        metrics.install(None)
        before = metrics.snapshot()
        raw = ForkingPickler.dumps(["synthetic", 1])
        self.assertEqual(ForkingPickler.loads(raw), ["synthetic", 1])
        after = metrics.snapshot()
        self.assertGreater(after["dump_ns"], before["dump_ns"])
        self.assertGreater(after["load_ns"], before["load_ns"])


if __name__ == "__main__":
    unittest.main()

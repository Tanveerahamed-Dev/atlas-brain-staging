"""Harness-only tests; psutil never enters the standard-library engine runtime."""
import unittest
from unittest.mock import Mock
import os
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import psutil
from tools.scale.measure import sample_memory, result_snapshot


class SamplerTests(unittest.TestCase):
    def test_prior_result_snapshot_detects_a_changed_file(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / "estate.json").write_bytes(b'{"prior":"intact"}\n')
            before = result_snapshot(directory)
            (directory / "estate.json").write_bytes(b'{"prior":"changed"}\n')
            self.assertNotEqual(before, result_snapshot(directory))

    def test_live_access_denial_is_fatal_to_measurement(self):
        process = Mock(pid=123)
        process.memory_full_info.side_effect = psutil.AccessDenied(123)
        process.wait.side_effect = psutil.TimeoutExpired(0.05, pid=123)
        with self.assertRaises(psutil.AccessDenied):
            sample_memory(process)

    def test_confirmed_exit_race_is_retained_separately(self):
        process = Mock(pid=123)
        process.memory_full_info.side_effect = psutil.AccessDenied(123)
        process.wait.return_value = 0
        memory, race = sample_memory(process)
        self.assertIsNone(memory)
        self.assertEqual(race, "confirmed_exit_after_access_denial")


if os.name == "nt":
    class WindowsJobTests(unittest.TestCase):
        def test_live_process_witness_cannot_report_zero_active(self):
            from tools.scale.windows_job import Job
            job = Job(0)
            process = None
            try:
                process = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                                           creationflags=0x4 | subprocess.CREATE_NEW_PROCESS_GROUP)
                job.assign_and_resume(process)
                self.assertGreater(job.active(), 0)
                process.kill()
                process.wait(timeout=5)
                for _ in range(20):
                    if job.active() == 0:
                        break
                    time.sleep(0.05)
                self.assertEqual(job.active(), 0)
            finally:
                job.close()
                if process is not None:
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

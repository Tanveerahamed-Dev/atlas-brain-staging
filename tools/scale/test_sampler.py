"""Harness-only tests; psutil never enters the standard-library engine runtime."""
import unittest
from unittest.mock import Mock
import psutil
from tools.scale.measure import sample_memory


class SamplerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

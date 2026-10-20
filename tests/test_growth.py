"""Planted measurement failures, before the worker-growth probe."""
import unittest


class GrowthTests(unittest.TestCase):
    def test_missing_worker_samples_are_not_a_no_recycle_decision(self):
        from tools.scale.growth import decide
        with self.assertRaisesRegex(ValueError, "incomplete_growth"):
            decide([], 4, 75)

    def test_more_than_quarter_growth_requires_recycling(self):
        from tools.scale.growth import decide
        rows = [{"pid": i, "tasks": 75, "baseline_rss": 100,
                 "plateau_peak_rss": peak, "sampled_peak_rss": peak}
                for i, peak in enumerate((100, 110, 125, 126))]
        self.assertTrue(decide(rows, 4, 75)["recycling_required"])
        rows[-1]["plateau_peak_rss"] = 125
        rows[-1]["sampled_peak_rss"] = 125
        self.assertFalse(decide(rows, 4, 75)["recycling_required"])

    def test_transient_peak_is_retained_but_does_not_count_as_accumulation(self):
        from tools.scale.growth import decide
        row = {"pid": 1, "tasks": 75, "baseline_rss": 100,
               "plateau_peak_rss": 100, "sampled_peak_rss": 130}
        result = decide([row], 1, 75)
        self.assertFalse(result["recycling_required"])
        self.assertEqual(result["max_transient_growth_fraction"], 0.3)

    def test_reused_pid_with_distinct_birth_identity_is_two_workers(self):
        from tools.scale.growth import decide
        rows = [{"pid": 1, "identity": generation, "tasks": 3, "baseline_rss": 100,
                 "plateau_peak_rss": 110, "sampled_peak_rss": 140} for generation in ("1", "2")]
        self.assertFalse(decide(rows, 2, 3)["recycling_required"])

    def test_incomplete_worker_is_refused(self):
        from tools.scale.growth import decide
        row = {"pid": 1, "tasks": 74, "baseline_rss": 100,
               "plateau_peak_rss": 100, "sampled_peak_rss": 100}
        with self.assertRaisesRegex(ValueError, "incomplete_growth"):
            decide([row], 1, 75)


if __name__ == "__main__":
    unittest.main()

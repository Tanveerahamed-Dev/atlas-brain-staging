"""A green installation must cover the whole declared lock set."""
import unittest


class LockedInstallTests(unittest.TestCase):
    def test_missing_and_wrong_development_tool_are_refused(self):
        from tools.scale.locked_install import validate
        lock = {"package": [{"name": "atlas-brain", "version": "0.0.0", "source": {"virtual": "."}},
                            {"name": "pytest", "version": "9.1.1", "source": {"registry": "https://pypi.org/simple"}}]}
        project = {"project": {"dependencies": []}, "dependency-groups": {"dev": ["pytest==9.1.1"]}}
        for installed in ({}, {"pytest": "0"}):
            with self.assertRaisesRegex(ValueError, "locked_install_mismatch"):
                validate(lock, project, installed, "dev")
        self.assertEqual(validate(lock, project, {"pytest": "9.1.1"}, "dev"), {"pytest": "9.1.1"})
        self.assertEqual(validate(lock, project, {}, "runtime"), {})


if __name__ == "__main__":
    unittest.main()

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

    def test_platform_marker_changes_the_real_closure(self):
        from tools.scale.locked_install import validate
        lock = {"package": [{"name": "pytest", "version": "9.1.1", "source": {"registry": "https://pypi.org/simple"},
                             "dependencies": [{"name": "colorama", "marker": "sys_platform == 'win32'"}]},
                            {"name": "colorama", "version": "0.4.6", "source": {"registry": "https://pypi.org/simple"}}]}
        project = {"dependency-groups": {"dev": ["pytest==9.1.1"]}}
        self.assertEqual(validate(lock, project, {"pytest": "9.1.1"}, "dev", "linux"), {"pytest": "9.1.1"})
        with self.assertRaisesRegex(ValueError, "locked_install_mismatch"):
            validate(lock, project, {"pytest": "9.1.1"}, "dev", "win32")

    def test_linux_only_root_dependency_is_not_required_on_windows(self):
        from tools.scale.locked_install import validate
        lock = {"package": [{"name": "mutmut", "version": "3.8.0", "source": {"registry": "https://pypi.org/simple"}}]}
        project = {"dependency-groups": {"dev": ["mutmut==3.8.0; sys_platform == 'linux'"]}}
        self.assertEqual(validate(lock, project, {}, "dev", "win32"), {})
        with self.assertRaisesRegex(ValueError, "locked_install_mismatch"):
            validate(lock, project, {}, "dev", "linux")


if __name__ == "__main__":
    unittest.main()

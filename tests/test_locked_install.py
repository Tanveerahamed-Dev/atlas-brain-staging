"""A green installation must cover the whole declared lock set."""
import unittest


class LockedInstallTests(unittest.TestCase):
    def test_startup_allowlist_requires_locked_owner_and_record_hash(self):
        from tools.scale.locked_install import validate_hooks
        row = {"owner": "coverage", "sha256": "a" * 64, "record_sha256": "a" * 64, "class": "executable"}
        self.assertEqual(validate_hooks([row], {"coverage": "7.16.2"}, "dev"), [row])
        with self.assertRaisesRegex(ValueError, "startup_hook_ownership"):
            validate_hooks([row], {}, "dev")
        with self.assertRaisesRegex(ValueError, "runtime_startup_code"):
            validate_hooks([row], {"coverage": "7.16.2"}, "runtime")
        with self.assertRaisesRegex(ValueError, "startup_hook_record_digest"):
            validate_hooks([dict(row, record_sha256="b" * 64)], {"coverage": "7.16.2"}, "dev")
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

    def test_transitive_extra_is_part_of_the_installed_closure(self):
        from tools.scale.locked_install import validate
        source = {"registry": "https://pypi.org/simple"}
        lock = {"package": [{"name": "tool", "version": "1", "source": source, "dependencies": [{"name": "lib", "extra": ["addon"]}]},
                            {"name": "lib", "version": "1", "source": source, "optional-dependencies": {"addon": [{"name": "extra-dep"}]}},
                            {"name": "extra-dep", "version": "1", "source": source}]}
        project = {"dependency-groups": {"dev": ["tool==1"]}}
        with self.assertRaisesRegex(ValueError, "locked_install_mismatch"):
            validate(lock, project, {"tool": "1", "lib": "1"}, "dev")
        complete = {"tool": "1", "lib": "1", "extra-dep": "1"}
        self.assertEqual(validate(lock, project, complete, "dev"), complete)


if __name__ == "__main__":
    unittest.main()

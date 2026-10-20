"""Planted startup and import-admission bypasses; unrelated to S0-b."""
from pathlib import Path
import tempfile
import unittest


class StartupTests(unittest.TestCase):
    def test_absent_optional_import_raises_import_error_without_executing_a_loader(self):
        from spike import admission, safety
        before = safety.VIOLATIONS
        with self.assertRaises(ModuleNotFoundError):
            admission.absent_import("planted_absent_optional")
        self.assertEqual(safety.VIOLATIONS, before)
        self.assertIn("planted_absent_optional", admission.ABSENT_IMPORTS)

    def test_direct_runtime_entry_cannot_claim_uninstalled_admission(self):
        from types import SimpleNamespace
        from spike.runtime import execute
        with self.assertRaisesRegex(ValueError, "runtime_admission_required"):
            execute(SimpleNamespace(), ())

    def test_swallowed_import_denial_still_counts(self):
        from spike import admission, safety
        before = safety.VIOLATIONS
        try:
            with self.assertRaises(admission.ImportDenied):
                admission.deny_import("planted_unlisted")
            self.assertEqual(safety.VIOLATIONS, before + 1)
            self.assertFalse(issubclass(admission.ImportDenied, Exception))
        finally:
            safety.VIOLATIONS = before

    def test_unexpected_startup_module_is_refused(self):
        from spike.admission import compare_startup
        with self.assertRaisesRegex(ValueError, "startup_module_baseline"):
            compare_startup(["sys", "planted_startup"], ["sys"])
        self.assertEqual(compare_startup(["sys"], ["sys"]), ["sys"])

    def test_stdlib_name_does_not_admit_an_external_shadow(self):
        from spike.admission import allowed_origin
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            stdlib = directory / "stdlib"
            stdlib.mkdir()
            self.assertTrue(allowed_origin("json", str(stdlib / "json" / "__init__.py"), [stdlib], {}, []))
            self.assertFalse(allowed_origin("json", str(directory / "json.py"), [stdlib], {}, []))
            self.assertFalse(allowed_origin("json", str(stdlib / "site-packages" / "json.py"), [stdlib], {}, [stdlib / "site-packages"]))

    def test_generated_stdlib_inventory_covers_new_interpreter_modules(self):
        from spike.admission import stdlib_names
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / "_generated_interpreter_metadata.py").write_bytes(b"data = {}\n")
            self.assertIn("_generated_interpreter_metadata", stdlib_names([directory]))

    def test_stdlib_inventory_covers_frozen_and_zip_classes(self):
        from spike.admission import stdlib_names
        import _imp
        import zipfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stdlib.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("_generated_zip_metadata.py", "data = {}\n")
            names = stdlib_names([path])
            self.assertIn("_generated_zip_metadata", names)
            self.assertTrue(set(_imp._frozen_module_names()) <= names)

    def test_unlisted_or_modified_engine_module_is_refused(self):
        from spike.admission import allowed_origin
        import hashlib
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "pack.py"
            path.write_bytes(b"value = 1\n")
            catalogue = {"spike.pack": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
            self.assertTrue(allowed_origin("spike.pack", str(path), [], catalogue, []))
            self.assertFalse(allowed_origin("spike.unlisted", str(path), [], catalogue, []))
            path.write_bytes(b"value = 2\n")
            self.assertFalse(allowed_origin("spike.pack", str(path), [], catalogue, []))

    def test_case_and_extension_hook_classes_are_refused(self):
        from spike.safety import census
        for name in ("hidden.PTH", "hidden.START", "sitecustomize.cpython-314-x86_64-linux-gnu.so", "sitecustomize"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                path = Path(root) / name
                if name == "sitecustomize":
                    path.mkdir()
                    (path / "__init__.py").write_bytes(b"import os\n")
                else:
                    path.write_bytes(b"import os\n")
                with self.assertRaisesRegex(ValueError, "startup_code_unadmitted"):
                    census([Path(root)])

    def test_findable_zip_startup_code_is_refused(self):
        from spike.safety import census
        import zipfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "startup.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("sitecustomize/__init__.py", "import os\n")
            with self.assertRaisesRegex(ValueError, "startup_code_unadmitted"):
                census([path])

    def test_prestart_census_follows_path_only_pth_without_running_it(self):
        from spike.safety import census
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            extra = directory / "extra"
            extra.mkdir()
            (extra / "sitecustomize.py").write_bytes(b"import os\n")
            (directory / "paths.pth").write_bytes(b"extra\n")
            with self.assertRaisesRegex(ValueError, "startup_code_unadmitted"):
                census([directory])


if __name__ == "__main__":
    unittest.main()

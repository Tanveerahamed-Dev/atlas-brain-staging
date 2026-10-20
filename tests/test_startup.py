"""Planted startup and import-admission bypasses; unrelated to S0-b."""
from pathlib import Path
import tempfile
import unittest


class StartupTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

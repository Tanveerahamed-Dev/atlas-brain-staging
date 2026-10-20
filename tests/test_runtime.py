"""Runtime guards have planted violations; this file does not seed S0-b."""
from pathlib import Path
import tempfile
import unittest

from spike.safety import census, verify_catalogue


class AdmissionTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.provenance import validate_tree


RAW = b"synthetic output\r\n"
RECORD = '''fixture_id: synthetic-example
file: output.txt
tier: S
source:
  kind: synthetic
  repository:
    url: "https://github.com/example/corpus"
    commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    path: "samples/output.txt"
platform:
  family: unstated
  model: unstated
  version: unstated
  version_basis: unknown
licence:
  name: "CC0-1.0"
  redistribution: public
  notice: "No notice required by source licence"
sha256: "HASH"
'''.replace("HASH", hashlib.sha256(RAW).hexdigest())


class ProvenanceTests(unittest.TestCase):
    def check_tree(self, record=RECORD, raw=RAW, extra=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            case = root / "example"
            case.mkdir(parents=True)
            (case / "output.txt").write_bytes(raw)
            if record is not None:
                (case / "provenance.yaml").write_text(record, encoding="utf-8")
            if extra:
                (case / extra).write_bytes(b"unrecorded")
            return validate_tree(root)

    def test_planted_missing_record(self):
        self.assertTrue(self.check_tree(None))

    def test_planted_hash_mismatch_and_line_ending_change(self):
        self.assertTrue(self.check_tree(raw=RAW.replace(b"\r\n", b"\n")))

    def test_every_required_field_is_enforced(self):
        for line in RECORD.splitlines(keepends=True):
            if line.strip():
                with self.subTest(field=line.strip().split(":")[0]):
                    self.assertTrue(self.check_tree(RECORD.replace(line, "", 1)))

    def test_planted_invalid_values(self):
        for old, new in [
            ("tier: S", "tier: excluded"), ("tier: S", "tier: H"),
            ("tier: S", "tier: L"), ("kind: synthetic", "kind: library_testdata"),
            ("redistribution: public", "redistribution: unknown"),
            ("redistribution: public", "redistribution: private_only"),
            ("redistribution: public", "redistribution: link_only"),
            ('name: "CC0-1.0"', 'name: ""'),
            ('notice: "No notice required by source licence"', "notice: null"),
            ('"' + "a" * 40 + '"', '"main"'),
            ("https://github.com/example/corpus", "file:///corpus"),
            ('path: "samples/output.txt"', 'path: "../output.txt"'),
            ("file: output.txt", "file: ../output.txt"),
            ("family: unstated", "family: iosxe"),
            ("version_basis: unknown", "version_basis: observed"),
        ]:
            with self.subTest(value=new):
                self.assertTrue(self.check_tree(RECORD.replace(old, new)))

    def test_planted_unsupported_yaml(self):
        for text in [
            RECORD + "tier: S\n", RECORD + "extra: value\n",
            RECORD.replace("tier: S", "tier: &anchor S"),
            RECORD.replace("tier: S", "tier: *anchor"),
            RECORD.replace("tier: S", "tier: [S]"),
            RECORD.replace("tier: S", "tier: {value: S}"),
            RECORD.replace("tier: S", "tier: S # comment"),
            RECORD.replace("tier: S", "tier: 'S'"),
            RECORD.replace("tier: S", "tier: |\n  S"),
            RECORD.replace("  kind:", "\tkind:"), "---\n" + RECORD,
            RECORD.replace("source:\n", "source: null\n"),
            RECORD.replace("source:\n", "source:\n    nested: value\n"),
        ]:
            with self.subTest(record=text):
                self.assertTrue(self.check_tree(text))

    def test_planted_unrecorded_extra_and_reserved_name(self):
        self.assertTrue(self.check_tree(extra="extra.txt"))
        self.assertTrue(self.check_tree(RECORD.replace("file: output.txt", "file: provenance.yaml")))

    def test_positive_synthetic_and_public_stated_or_unstated(self):
        self.assertEqual(self.check_tree(), [])
        public = RECORD.replace("tier: S", "tier: P").replace("kind: synthetic", "kind: library_testdata")
        self.assertEqual(self.check_tree(public), [])
        stated = public.replace("family: unstated", "family: iosxe").replace("model: unstated", "model: C8000V").replace("version: unstated", 'version: "17.1"').replace("version_basis: unknown", "version_basis: source_stated")
        self.assertEqual(self.check_tree(stated), [])

    def test_cli_refuses_orphan_record_and_missing_explicit_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            result = subprocess.run([sys.executable, "tools/provenance.py", str(root)], capture_output=True)
            self.assertEqual(result.returncode, 1)
            root.mkdir()
            self.assertEqual(validate_tree(root), [])
            (root / "provenance.yaml").write_text(RECORD, encoding="utf-8")
            self.assertTrue(validate_tree(root))

    @unittest.skipIf(sys.platform == "win32", "symlinks need Windows developer privileges")
    def test_planted_symlink_file_directory_and_root(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "fixtures"
            root.mkdir()
            target = Path(folder) / "target"
            target.mkdir()
            link = root / "linked"
            link.symlink_to(target, target_is_directory=True)
            self.assertTrue(validate_tree(root))
            self.assertTrue(validate_tree(link))
            link.unlink()
            (root / "dangling.txt").symlink_to(target / "missing")
            self.assertTrue(validate_tree(root))

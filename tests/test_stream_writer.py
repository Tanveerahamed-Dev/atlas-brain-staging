"""The bounded memory-profile change must preserve exact canonical bytes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class StreamWriterTests(unittest.TestCase):
    def test_node_stream_matches_canonical_without_a_whole_document_dump(self):
        from spike.runtime import write_node
        from tools.scale.workload import canonical
        value = {"schema": 1, "node": "sw-00001", "captures": [["unicode-\u00e9", "a" * 64, 12]],
                 "accounting": [[0, {"consumed": 2, "unrecognized": 0}]],
                 "facts": [["kind", ("quote\"slash\\", "\u7f51"), 0, i, i + 1, i + 1] for i in range(4000)]}
        expected = canonical(value)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "node.json"
            with patch("json.dumps", side_effect=AssertionError("whole_document_copy")):
                count = write_node(path, value)
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(count, len(expected))


if __name__ == "__main__":
    unittest.main()

import json
import os
import subprocess
import sys

import pytest

from tools.privacy import scan


@pytest.mark.parametrize("data", [
    b"C:" + bytes([92]) + b"Users" + bytes([92]) + b"example/file",
    b"/" + b"home/example/file", b"/" + b"Users/example/file",
    b".".join([b"10", b"1", b"2", b"3"]), b"fc" + b"00::1",
    b"FOC" + b"1234ABCD",
])
def test_planted_structural_shapes(data):
    assert scan(data, "a" * 40, [])


@pytest.mark.parametrize("data", [b"192.0.2.1", b"198.51.100.5", b"203.0.113.8", b"2001:db8::1"])
def test_documentation_addresses_pass(data):
    assert not scan(data, "b" * 40, [])


def test_gate_marker_and_split_receipts():
    marker = os.environ["ATLAS_TEST_MARKER"].encode()
    for data in (b"prefix " + marker, b'v = "' + marker[:5] + b'" + "' + marker[5:] + b'"',
                 b'v = "' + marker[:5] + b'" "' + marker[5:] + b'"'):
        hits = scan(data, "c" * 40, [marker])
        assert hits == [{"blob": "c" * 40, "offset": data.index(marker[:5])}]
        assert marker.decode() not in json.dumps(hits)
        assert not scan(data, "c" * 40, [])


@pytest.mark.parametrize("gate", [True, False])
def test_cli_refuses_planted_blob(tmp_path, gate):
    marker = os.environ["ATLAS_TEST_MARKER"]
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    data = marker if gate else "/" + "home/example/file"
    (repo / "sample.txt").write_text(data, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    tool = os.path.abspath("tools/privacy.py")
    result = subprocess.run([sys.executable, tool, *(["--gate"] if gate else [])], cwd=repo,
                            env={**os.environ, "ATLAS_PRIVACY_MARKERS": json.dumps([marker])},
                            capture_output=True, check=False)
    assert result.returncode == 1
    assert marker.encode() not in result.stdout + result.stderr
    assert json.loads(result.stdout)[0]["offset"] == 0


def test_gate_without_markers_fails_closed():
    result = subprocess.run([sys.executable, "tools/privacy.py", "--gate"],
                            env={k: v for k, v in os.environ.items() if k != "ATLAS_PRIVACY_MARKERS"},
                            capture_output=True, check=False)
    assert result.returncode == 2

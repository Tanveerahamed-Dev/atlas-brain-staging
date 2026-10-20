"""Capture metadata witnesses, prepared before the constructor changes."""
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256

import pytest
from test_evidence import bundle

from atlas_brain.evidence import admission as a
from atlas_brain.evidence.capture import Channel, Scope
from atlas_brain.kernel import states as k


def capture(tmp_path, raw=b"record\n"):
    bundle(tmp_path, raw)
    return a.import_folder(tmp_path, a.Budgets(10000, 10000, 10)).captures[0]


def test_cli_capture_metadata_and_raw_witness(tmp_path):
    item = capture(tmp_path)
    assert item.channel is Channel.CLI
    assert item.scope.node == item.source == k.EntityKey("node:sw-a")
    assert item.scope.plane == "exec"
    assert item.scope.vrf is None
    assert item.error is None and item.envelope is None
    assert item.read_scope is k.ReadScope.UNKNOWN
    assert item.read_scope_evidence == ()
    assert item.view is k.ViewConsistency.UNKNOWN
    witness, = item.integrity_evidence
    assert witness.capture == item.id
    assert type(witness.locator) is k.WholeCapture
    assert witness.excerpt_sha256 == item.bytes_sha256 == sha256(item.raw).hexdigest()
    assert item.byte_len == len(item.raw)
    assert item.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert item.collected_utc.detail == "no_collector_time"
    assert item.collected_utc.evidence == (witness,)
    assert item.channel.value == "cli"
    with pytest.raises(FrozenInstanceError):
        item.raw = b"changed"


def test_identity_changes_with_capture_content(tmp_path):
    before = capture(tmp_path)
    after_folder = tmp_path / "second"
    after_folder.mkdir()
    bundle(after_folder, b"changed\n")
    after = a.import_folder(after_folder, a.Budgets(10000, 10000, 10)).captures[0]
    assert after.id != before.id


@pytest.mark.parametrize("change", [
    {"source": k.EntityKey("node:other")}, {"channel": "cli"},
    {"integrity": "empty"}, {"read_scope": "unknown"}, {"view": "unknown"},
    {"raw": bytearray(b"record\n")}, {"integrity_evidence": ()},
    {"envelope": {}}, {"operation": ""}, {"error": "timeout"},
    {"id": ""}, {"rendered": ""}, {"codec": ""}, {"collected_utc": None},
    {"read_scope": k.ReadScope.FULL_EVIDENCED},
])
def test_planted_invalid_capture_metadata_refuses(tmp_path, change):
    with pytest.raises((TypeError, ValueError)):
        replace(capture(tmp_path), **change)


@pytest.mark.parametrize("change", [{"node": ""}, {"plane": "other"}, {"vrf": ""}, {"afi": 4}])
def test_planted_invalid_scope_refuses(change):
    scope = Scope(node=k.EntityKey("node:sw-a"), vrf=None, context=None, vdc=None,
                  tenant=None, afi=None, instance=None, plane="exec")
    with pytest.raises((TypeError, ValueError)):
        replace(scope, **change)


def test_planted_witness_cannot_name_another_capture(tmp_path):
    item = capture(tmp_path)
    witness, = item.integrity_evidence
    with pytest.raises(ValueError, match="capture_witness_mismatch"):
        replace(item, integrity_evidence=(replace(witness, capture=k.CaptureId("cap:other")),))


def test_cli_integrity_witness_can_bind_an_exact_raw_span(tmp_path):
    item = capture(tmp_path)
    witness, = item.integrity_evidence
    span = k.ByteSpan(start=0, end=6)
    witness = replace(witness, locator=span, excerpt_sha256=sha256(b"record").hexdigest())
    result = replace(item, integrity_evidence=(witness,))
    assert result.integrity_evidence[0].locator == span


@pytest.mark.parametrize("locator,digest", [
    (k.ByteSpan(start=0, end=100), sha256(b"record").hexdigest()),
    (k.ByteSpan(start=0, end=6), "a" * 64),
    (k.WholeCapture(), "a" * 64),
    (k.FieldPointer(pointer="/record"), sha256(b"record\n").hexdigest()),
    (k.XmlPath(path="/record[1]"), sha256(b"record\n").hexdigest()),
])
def test_planted_invalid_cli_witness_locator_or_digest_refuses(tmp_path, locator, digest):
    item = capture(tmp_path)
    witness, = item.integrity_evidence
    with pytest.raises(ValueError):
        replace(item, integrity_evidence=(replace(witness, locator=locator, excerpt_sha256=digest),))

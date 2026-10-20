"""Manifest-v2 source metadata uses the canonical kernel interval record."""
import json

import pytest
from test_evidence import bundle

from atlas_brain.evidence.admission import AdmissionRefused, Budgets, import_folder
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval


def metadata_bundle(tmp_path, interval):
    manifest = bundle(tmp_path, b"record\n")
    manifest["version"] = 2
    manifest["captures"][0].update(scope={"vrf": "blue", "context": None, "vdc": None,
        "tenant": None, "afi": "ipv4", "instance": None, "plane": "exec"}, collected_utc=interval)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def recorded():
    return {"earliest": 10, "latest": 20, "clock": "collector:synthetic", "bound": "collector_recorded"}


def test_source_interval_is_canonical_and_scope_is_declared(tmp_path):
    manifest = metadata_bundle(tmp_path, recorded())
    item = import_folder(tmp_path, Budgets(10000, 10000, 10)).captures[0]
    assert type(item.collected_utc) is TimeInterval
    assert item.collected_utc == TimeInterval(earliest=10, latest=20, clock="collector:synthetic", bound=BoundSource.COLLECTOR_RECORDED)
    assert item.scope.vrf == "blue" and item.scope.afi == "ipv4"
    assert item.read_scope is k.ReadScope.UNKNOWN and item.view is k.ViewConsistency.UNKNOWN
    manifest["captures"][0]["collected_utc"]["latest"] = 21
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert import_folder(tmp_path, Budgets(10000, 10000, 10)).captures[0].id != item.id


def test_missing_source_time_stays_evidenced_unknown(tmp_path):
    metadata_bundle(tmp_path, None)
    item = import_folder(tmp_path, Budgets(10000, 10000, 10)).captures[0]
    assert type(item.collected_utc) is k.Unknown
    assert item.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert item.collected_utc.evidence


@pytest.mark.parametrize("change", [{"earliest": True}, {"earliest": 30}, {"latest": None},
    {"clock": ""}, {"clock": "node:sw-a/epoch:one"}, {"bound": "per_event_quality"}, {"extra": 1}])
def test_planted_invalid_source_time_refuses_bundle(tmp_path, change):
    metadata_bundle(tmp_path, recorded() | change)
    with pytest.raises(AdmissionRefused):
        import_folder(tmp_path, Budgets(10000, 10000, 10))


@pytest.mark.parametrize("change", [{"plane": "other"}, {"vrf": ""}, {"afi": 4}, {"extra": "unknown"}])
def test_planted_invalid_source_scope_refuses_bundle(tmp_path, change):
    manifest = metadata_bundle(tmp_path, recorded())
    manifest["captures"][0]["scope"].update(change)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AdmissionRefused):
        import_folder(tmp_path, Budgets(10000, 10000, 10))

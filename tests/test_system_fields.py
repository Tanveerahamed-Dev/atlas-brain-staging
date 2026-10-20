"""Synthetic field-extraction cases; these do not establish a platform floor."""
from hashlib import sha256

from atlas_brain.packs.platform.system.parsers.show_version import Unit, extract_fields

from atlas_brain.kernel.states import (
    CaptureId,
    EvidenceRef,
    Known,
    Unknown,
    UnknownReason,
)

CAPTURE = CaptureId("synthetic-cap-a")
RAW = (b'sw-a uptime is 1 day, 2 hours, 3 minutes\r\n'
       b'System image file is "bootflash:packages.conf"\r\n'
       b'Last reload reason: PowerOn\r\n')


def test_missing_fields_and_boot_epoch_never_become_defaults():
    result = extract_fields(b"", CAPTURE)
    for fact in (result.uptime, result.image, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.FIELD_NOT_PRINTED
    assert isinstance(result.boot_epoch, Unknown)
    assert result.boot_epoch.reason is UnknownReason.NOT_COLLECTED


def test_positive_observed_fields_round_trip_to_original_bytes():
    result = extract_fields(RAW, CAPTURE)
    assert result.parse.quality == "complete"
    assert isinstance(result.uptime, Known)
    assert result.uptime.value == ((1, Unit.DAY), (2, Unit.HOUR), (3, Unit.MINUTE))
    assert isinstance(result.image, Known)
    assert result.image.value == "bootflash:packages.conf"
    assert isinstance(result.reload_reason, Known)
    assert result.reload_reason.value == "PowerOn"
    for fact in (result.uptime, result.image, result.reload_reason):
        for evidence in fact.evidence:
            assert isinstance(evidence, EvidenceRef)
            excerpt = RAW[evidence.locator.start:evidence.locator.end]
            assert sha256(excerpt).hexdigest() == evidence.excerpt_sha256
    assert isinstance(result.boot_epoch, Unknown)
    assert not hasattr(result, "family")
    assert not hasattr(result, "train")
    assert not hasattr(result, "mode")


def test_unmapped_unit_keeps_raw_and_is_partial():
    result = extract_fields(b"sw-a uptime is 2 fortnights\n", CAPTURE)
    assert isinstance(result.uptime, Unknown)
    assert result.uptime.reason is UnknownReason.PARSE_PARTIAL
    assert result.parse.quality == "partial"
    assert result.parse.tokens[0][1].raw == "fortnights"


def test_duplicate_and_reversed_units_are_refused():
    for value in (b"1 day, 2 days", b"1 minute, 2 hours", b"one day", b"9007199254740992 seconds", b"9" * 5000 + b" seconds"):
        result = extract_fields(b"sw-a uptime is " + value + b"\n", CAPTURE)
        assert isinstance(result.uptime, Unknown)
        assert result.parse.quality == "partial"


def test_duplicate_fields_are_conflicting_even_if_values_match():
    result = extract_fields(RAW + RAW, CAPTURE)
    for fact in (result.uptime, result.image, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.CONFLICTING_EVIDENCE
        assert len(fact.evidence) == 2


def test_unrecognised_line_stays_visible_and_lf_offsets_are_stable():
    for raw in (RAW + b"new firmware line\n", RAW.replace(b"\r\n", b"\n") + b"new firmware line"):
        result = extract_fields(raw, CAPTURE)
        assert result.parse.quality == "partial"
        assert result.parse.lines[-1].status == "unrecognised"
        span = result.parse.lines[-1].span
        assert raw[span.start:span.end].startswith(b"new firmware line")
        assert isinstance(result.image, Known)


def test_invalid_text_is_not_promoted_to_a_known_image():
    result = extract_fields(b'System image file is "\xff"\n', CAPTURE)
    assert isinstance(result.image, Unknown)
    assert result.image.reason is UnknownReason.PARSE_PARTIAL

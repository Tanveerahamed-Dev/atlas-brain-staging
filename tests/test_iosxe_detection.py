"""Synthetic detection/envelope controls, never device-format floor evidence."""
import pytest

from atlas_brain.kernel.states import (
    CaptureId,
    IntegrityState,
    Known,
    Unknown,
    UnknownReason,
)
from atlas_brain.platform.iosxe import (
    classify,
    detect,
    detection_version,
    interface_name,
    prompt_mode,
)

CAPTURE = CaptureId("cap-a")
XE16 = b"Cisco IOS XE Software, Version 16.10.1\n"


@pytest.mark.parametrize("raw,family", [
    (b"Cisco IOS Software, generic image, Version Denali 16.2.1\n", "iosxe"),
    (XE16, "iosxe"),
    (b"Cisco IOS XE Software, Version 17.09.05a\n", "iosxe"),
    (b"Cisco IOS Software, IOS-XE Software (generic image), Version 15.5(3)S\n"
     b"IOS XE Version: 03.16.04.S\n", "iosxe"),
    (b"Cisco IOS Software, generic image, Version 12.2(55)SE\n", "ios"),
    (b"Cisco IOS Software, generic image, Version 15.2(4)E\n", "ios"),
])
def test_r10_exact_family_markers_never_default_to_ios(raw, family):
    result = detect(raw, CAPTURE)
    assert isinstance(result, Known)
    assert result.value == family


def test_banner_without_either_family_marker_is_unknown():
    result = detect(b"unknown software banner\n", CAPTURE)
    assert isinstance(result, Unknown)
    assert result.reason is UnknownReason.PLATFORM_UNKNOWN


def test_dual_version_selects_xe_train_never_first_iosd_version():
    raw = (b"Cisco IOS Software, IOS-XE Software (generic image), Version 15.5(3)S\n"
           b"IOS XE Version: 03.16.04.S\n")
    result = detection_version(raw, CAPTURE)
    assert isinstance(result, Known)
    assert result.value == result.raw == "03.16.04.S"
    span = result.evidence[0].locator
    assert raw[span.start:span.end] == b"03.16.04.S"


def test_conflicting_version_records_never_pick_a_winner():
    raw = XE16 + b"Cisco IOS XE Software, Version 17.09.05a\n"
    assert isinstance(detect(raw, CAPTURE), Unknown)
    assert isinstance(detection_version(raw, CAPTURE), Unknown)


@pytest.mark.parametrize("hazard,state", [
    (b"% Invalid input detected at '^' marker.\n", IntegrityState.ERROR),
    (b"% Incomplete command.\n", IntegrityState.ERROR),
    (b'% Ambiguous command: "show con"\n', IntegrityState.ERROR),
    (b"--More--", IntegrityState.PAGING_ARTIFACTS),
])
def test_failed_or_paged_capture_never_yields_a_family_claim(hazard, state):
    raw = XE16 + hazard
    assert classify(raw) is state
    assert isinstance(detect(raw, CAPTURE), Unknown)
    assert isinstance(detection_version(raw, CAPTURE), Unknown)


def test_prompt_is_not_family_success_scope_or_completeness():
    assert prompt_mode(b"sw-a(config-if)#") == "config_if"
    assert prompt_mode(b"sw-a# show version") is None
    assert classify(b"sw-a#") is IntegrityState.UNVERIFIED_PROMPT
    assert isinstance(detect(b"sw-a#", CAPTURE), Unknown)
    assert classify(b"message: % Incomplete command.\n") is IntegrityState.UNKNOWN_FORMAT
    assert classify(b"") is IntegrityState.EMPTY


def test_lone_cr_does_not_turn_a_malformed_version_line_into_a_match():
    assert isinstance(detect(XE16.rstrip(b"\n") + b"\r", CAPTURE), Unknown)


def test_unrecognised_xe_version_is_not_a_supported_release():
    raw = b"Cisco IOS XE Software, Version 18.0.1\n"
    assert isinstance(detect(raw, CAPTURE), Unknown)
    assert isinstance(detection_version(raw, CAPTURE), Unknown)


def test_special_build_is_kept_verbatim_never_relabelled_as_a_release():
    raw = b"Cisco IOS XE Software, Version BLD_V1610_TEST\n"
    version = detection_version(raw, CAPTURE)
    assert isinstance(version, Known)
    assert version.value == version.raw == "BLD_V1610_TEST"


def test_conflicting_family_markers_are_unknown():
    raw = XE16 + b"Cisco Nexus Operating System (NX-OS) Software\n"
    result = detect(raw, CAPTURE)
    assert isinstance(result, Unknown)
    assert result.reason is UnknownReason.IDENTITY_AMBIGUOUS


@pytest.mark.parametrize("raw,canonical", [
    (b"Gi1/0/1", "GigabitEthernet1/0/1"),
    (b"TenGigabitEthernet0/0/0.10", "TenGigabitEthernet0/0/0.10"),
    (b"HundredGigE1/0/1/1", "HundredGigE1/0/1/1"),
])
def test_interface_subset_uses_only_family_spellings_and_no_speed_inference(raw, canonical):
    assert interface_name(raw) == canonical


@pytest.mark.parametrize("raw", [b"Tw1/0/1", b"Twe1/0/1", b"Eth1/1", b"Gi01/0/1", b"Gi1//1", b"Gi1/0/1\n"])
def test_unknown_or_ambiguous_interface_is_not_passed_through(raw):
    assert interface_name(raw) is None

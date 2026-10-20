"""Planted NX false claims and fail-closed envelope/grammar cases."""
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.kernel.states import CaptureId, IntegrityState, Known, Unknown
from atlas_brain.platform.nxos import classify, detect, interface_name, prompt_mode

CAP = CaptureId("public-a")
BANNER = b"Cisco Nexus Operating System (NX-OS) Software\n"


@pytest.mark.parametrize("raw", [
    b"Cisco IOS Software, IOS-XE Software, Version 03.16.00.S\n",
    b"Cisco IOS XE Software, Version 17.12.1\n",
    b"Cisco IOS Software, Version 15.2\n", b"unidentified software\n", b"",
    b"NXOS: version 10.3(2)\n", BANNER,
    BANNER + b"NXOS: version 8.4(1)\n",
    BANNER + b"NXOS: version 110.3(2)\n",
    BANNER + b"NXOS: version 10.3\n",
    BANNER + b"NXOS: version 10.3(2)\nNXOS: version 8.4(1)\n",
    BANNER + b"NXOS: version 10.3(2)\nNXOS: version 9.3(7)\n",
    BANNER + b"NXOS: version 10.3(2)\nCisco IOS XE Software, Version 17.1\n",
])
def test_planted_iosxe_and_unknown_are_never_claimed(raw):
    assert isinstance(detect(raw, CAP), Unknown)


@pytest.mark.parametrize("version", [b"9.3(7a)", b"10.3(2)", b"10.5(1)F"])
def test_nxos_detection_keeps_positive_byte_evidence(version):
    raw = BANNER + b"  NXOS: version " + version + b"\r\n"
    result = detect(raw, CAP)
    assert isinstance(result, Known) and result.value == "nxos"
    for ref in result.evidence:
        span = ref.locator
        assert sha256(raw[span.start:span.end]).hexdigest() == ref.excerpt_sha256


@pytest.mark.parametrize("error", [
    b"% Invalid command at '^' marker.",
    b"% Invalid input detected at '^' marker.", b"% Incomplete command",
    b"% invalid command detected at '^' marker.",
])
def test_d02_both_error_styles_are_rejected(error):
    assert classify(b"sw-a# show interface\n" + error + b"\r\n") is IntegrityState.ERROR


def test_pager_and_prompt_are_not_data_or_empty_success():
    assert classify(b"nve1 is up\n--More--\x08\x08") is IntegrityState.PAGING_ARTIFACTS
    assert classify(b"% Incomplete command\n--More--") is IntegrityState.ERROR
    assert classify(b"sw-a(config-if)#\n") is IntegrityState.UNVERIFIED_PROMPT
    assert classify(b"sw-a#\n") is IntegrityState.UNVERIFIED_PROMPT
    assert classify(b"") is IntegrityState.EMPTY
    assert classify(b"nve1 is up\n") is IntegrityState.UNKNOWN_FORMAT
    assert classify(b"Description: % Incomplete command\n") is IntegrityState.UNKNOWN_FORMAT


@pytest.mark.parametrize("name", ["Eth101/1/2", "Ethernet1/1/1", "Ethernet1/2.100",
                                      "Eth1/1", "Vlan100", "port-channel10", "mgmt0", "nve1"])
def test_interface_subset_preserves_names_without_speed_inference(name):
    assert interface_name(name.encode()) == name


@pytest.mark.parametrize("name", [b"Gi1/0/1", b"Eth1/1/1/1", b"Eth0/1", b"Eth1/0",
                                      b"Eth1/1 trailing", b"Ethernet", b"nve1\n", b"Vlan0"])
def test_outside_interface_subset_is_not_normalised_or_guessed(name):
    assert interface_name(name) is None


def test_prompt_modes_and_command_echo_are_distinct():
    assert prompt_mode(b"sw-a# ") == "exec"
    assert prompt_mode(b"sw-a(config-subif)#") == "config"
    assert prompt_mode(b"loader>") == "loader"
    assert prompt_mode(b"sw-a-tcl#") == "tcl"
    assert prompt_mode(b"sw-a# show interface") is None
    assert prompt_mode(b"ordinary data #") is None


@pytest.mark.parametrize("folder, digest", [
    ("show-interface", "29a640c1c921fa7e6c685b6295f41c2b6898b57d2da290304c90ed6febbe7485"),
    ("show-interface-switchport", "d46c2eca027929f23222df0a27526e2ae15545a019f43731a6912752fc940fdf"),
])
def test_two_q_public_samples_keep_exact_bytes_and_grammar(folder, digest):
    root = Path("fixtures/tier-p/nxos") / folder
    raw = (root / "raw.txt").read_bytes()
    assert sha256(raw).hexdigest() == digest
    provenance = (root / "provenance.yaml").read_text()
    assert 'tier: P' in provenance and 'format_floor: false' in provenance
    names = [line[6:] if line.startswith(b"Name: ") else line.split(b" is ")[0]
             for line in raw.splitlines() if line.startswith(b"Name: ") or b" is " in line]
    assert names and all(interface_name(name) is not None for name in names)


@pytest.mark.parametrize("denial", [b"% Permission denied for the role", b"%Permission denied for the role"])
def test_r_research_denials_are_not_empty_success(denial):
    assert classify(denial) is IntegrityState.ERROR


def test_unattested_period_variant_stays_unknown_and_no_failure_claims_family():
    assert classify(b"% Incomplete command.\n") is IntegrityState.UNKNOWN_FORMAT
    for suffix in (b"% Incomplete command\n", b"--More--"):
        assert isinstance(detect(BANNER + b"NXOS: version 10.3(2)\n" + suffix, CAP), Unknown)

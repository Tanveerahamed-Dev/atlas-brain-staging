"""NX-OS 9.x/10.x adapter primitives; full identity dispatch belongs to runner.

Signatures: Cisco N9K 10.5 fundamentals, Understanding the Command-Line
Interface (CLI prompt, modes, context-sensitive help, --More-- sections).
https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/configuration/fundamentals/cisco-nexus-9000-series-nx-os-fundamentals-configuration-guide-release-105x/m-understanding-the-cli.html
Source selection follows R's error-signatures research (NX-01 through NX-06).
P fixtures with unstated versions establish robustness, never a 9.x/10.x floor.
"""
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import Rule, run_rules
from atlas_brain.kernel.states import (
    Basis,
    CaptureId,
    EvidenceRef,
    EvidenceRole,
    IntegrityState,
    Known,
    Unknown,
    UnknownReason,
    WholeCapture,
)

ERROR_SIGNATURES = (
    b"% Invalid command at '^' marker.",
    b"% Invalid input detected at '^' marker.",
    b"% Incomplete command", b"% invalid command detected at '^' marker.",
)
DENIAL_SIGNATURES = (b"% Permission denied for the role", b"%Permission denied for the role")
PAGER_SIGNATURES = (b"--More--",)
_PROMPT_EXEC = compile_pattern(r"[A-Za-z0-9_][A-Za-z0-9_.-]*+#[ \t]*+")
_PROMPT_CONFIG = compile_pattern(r"[A-Za-z0-9_][A-Za-z0-9_.-]*+\(config[^()\r\n]*+\)#[ \t]*+")
_INTERFACE_PATTERNS = tuple(compile_pattern(pattern) for pattern in (
    *(prefix + suffix for prefix in ("Eth", "Ethernet") for suffix in (
        r"[1-9][0-9]*+/[1-9][0-9]*+",
        r"[1-9][0-9]*+/[1-9][0-9]*+/[1-9][0-9]*+",
        r"[1-9][0-9]*+/[1-9][0-9]*+\.[1-9][0-9]*+",
    )),
    r"Vlan[1-9][0-9]*+", r"port-channel[1-9][0-9]*+", r"mgmt0", r"nve[1-9][0-9]*+",
))
_VERSION_SUFFIXES = ("", r" \[Feature Release\]", r" \[Maintenance Release\]",
                     r" \[build [^\]\r\n]++\]")
_DETECTION_RULES = (
    Rule("nx-banner", "start", r"Cisco Nexus Operating System \(NX-OS\) Software[ \t]*+",
         "record", "start", "", ()),
    *(Rule(f"nx-version-valid-{major}-{index}", "start",
           r"[ \t]*+NXOS: version (?P<version>" + major
           + r"\.[0-9]++\([0-9A-Za-z.]++\)[A-Za-z0-9]*+)" + suffix + r"[ \t]*+",
           "record", "start", "", ("version",))
      for major in ("9", "10") for index, suffix in enumerate(_VERSION_SUFFIXES)),
    Rule("nx-version-outside-subset", "start", r"[ \t]*+NXOS: version[^\r\n]*+",
         "record", "start", "", ()),
    Rule("other-family", "start", r"[ \t]*+Cisco IOS[^\r\n]*+", "record", "start", "", ()),
)

def prompt_mode(line: bytes) -> Literal["exec", "config", "loader", "tcl"] | None:
    """A prompt alone; command echoes and unrecognised modes remain unverified."""
    if line == b"loader>":
        return "loader"
    if line.rstrip(b" \t").endswith(b"-tcl#") and _PROMPT_EXEC.fullmatch(line):
        return "tcl"
    if _PROMPT_CONFIG.fullmatch(line):
        return "config"
    if _PROMPT_EXEC.fullmatch(line):
        return "exec"
    return None


def interface_name(raw: bytes) -> str | None:
    """Validate the subset, preserving spelling; no alias, speed or role inference."""
    if any(pattern.fullmatch(raw) for pattern in _INTERFACE_PATTERNS):
        return raw.decode("ascii")
    return None


def classify(raw: bytes) -> IntegrityState:
    """Inspect one command-response segment, never arbitrary logs/configuration.

    Matches are envelope hazards only; recognised data never proves completeness.
    Prompt shapes remain unverified until bound to a collector/session.
    """
    lines = tuple(line.removesuffix(b"\r") for line in raw.split(b"\n"))
    if any(line.strip(b" \t") in (*ERROR_SIGNATURES, *DENIAL_SIGNATURES) for line in lines):
        return IntegrityState.ERROR
    if any(signature in raw for signature in PAGER_SIGNATURES):
        return IntegrityState.PAGING_ARTIFACTS
    if any(prompt_mode(line) is not None for line in lines):
        return IntegrityState.UNVERIFIED_PROMPT
    if not raw:
        return IntegrityState.EMPTY
    return IntegrityState.UNKNOWN_FORMAT


def detect(raw: bytes, capture: CaptureId) -> Known[str] | Unknown:
    """Evidence-backed family claim only; no substitute PlatformIdentity type.

    The shared identity/view contract has not landed. This primitive requires
    the NX banner and a supported NXOS version line from one detection capture.
    Parsing show-version inventory fields remains platform.system's work.
    """
    parsed = run_rules(raw, capture, _DETECTION_RULES, ())
    banners = tuple(row for row in parsed.records if row.rule_id == "nx-banner")
    versions = tuple(row for row in parsed.records if row.rule_id.startswith("nx-version-valid-"))
    conflicts = tuple(row for row in parsed.records if row.rule_id in ("other-family", "nx-version-outside-subset"))
    state = classify(raw)
    if banners and versions and not conflicts and state not in (
        IntegrityState.ERROR, IntegrityState.PAGING_ARTIFACTS,
    ) and len({row.fields[0][1].raw for row in versions}) == 1:
        evidence = tuple(EvidenceRef(
            capture=capture, locator=row.span, role=EvidenceRole.SUBJECT,
            excerpt_sha256=sha256(raw[row.span.start:row.span.end]).hexdigest(),
        ) for row in (*banners, *versions))
        return Known(value="nxos", basis=Basis.OBSERVED, evidence=evidence, raw="Cisco Nexus Operating System (NX-OS) Software")
    return Unknown(reason=UnknownReason.PLATFORM_UNKNOWN, detail="nxos_subset_unclaimed",
                   evidence=(EvidenceRef(capture=capture, locator=WholeCapture(),
                                         role=EvidenceRole.SUBJECT,
                                         excerpt_sha256=sha256(raw).hexdigest()),),
                   candidates=(), next_evidence=())

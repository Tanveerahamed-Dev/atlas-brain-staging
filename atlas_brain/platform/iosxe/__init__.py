"""IOS-XE detection/envelope primitives; no registered format-floor claim.

Sources: S4 D-01 / R10 and Cisco's IOS/XE release-banner examples:
https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ios-infoleak
Error/prompt/pager starting points: R's error-signatures research, XE-01..03,
PG-01 and PX-01..06; 17.18 CLI command reference and 17.x CLI-search guide.
These are lexical primitives, not a substitute PlatformIdentity/CaptureView.
Classic IOS is identified for R10; it does not gain IOS-XE parser support.
"""
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import Captured, ParseResult, Rule, run_rules
from atlas_brain.kernel.states import (
    Basis,
    ByteSpan,
    CaptureId,
    EvidenceRef,
    EvidenceRole,
    IntegrityState,
    Known,
    Unknown,
    UnknownReason,
    WholeCapture,
)

ERROR_SIGNATURES = (b"% Invalid input detected at '^' marker.", b"% Incomplete command.")
PAGER_SIGNATURES = (b"--More--",)
_PROMPTS = tuple((mode, compile_pattern(r"[A-Za-z0-9_][A-Za-z0-9_.-]*+" + suffix + r"[ \t]*+"))
                 for mode, suffix in (
                     ("user_exec", ">"), ("privileged_exec", "#"),
                     ("config", r"\(config\)#"), ("config_if", r"\(config-if\)#"),
                     ("config_line", r"\(config-line\)#"), ("config_vlan", r"\(config-vlan\)#"),
                 ))
_VERSION_SHAPES = tuple(compile_pattern(pattern) for pattern in (
    *(major + r"\.[0-9]++\.[0-9]++[A-Za-z0-9()._-]*+" for major in ("0?+3", "16", "17")),
    r"BLD_[A-Za-z0-9_]++",
))
_RULES = (
    Rule("xe-inline", "start", r"(?P<xe_banner>Cisco IOS Software, IOS-XE Software)[^\r\n]*+",
         "record", "start", "", ("xe_banner",)),
    Rule("xe-current", "start", r"(?P<xe_banner>Cisco IOS XE Software), Version (?P<xe_version>[^\r\n \t,]++)[^\r\n]*+",
         "record", "start", "", ("xe_banner", "xe_version")),
    Rule("xe-legacy", "start", r"(?P<xe_banner>IOS XE Version:) (?P<xe_version>[^\r\n \t,]++)[^\r\n]*+",
         "record", "start", "", ("xe_banner", "xe_version")),
    Rule("xe-denali", "start", r"(?P<xe_banner>Cisco IOS Software, [^,\r\n]++, Version Denali) "
         r"(?P<xe_version>16\.[0-9]++\.[0-9]++[A-Za-z0-9._-]*+)[^\r\n]*+",
         "record", "start", "", ("xe_banner", "xe_version")),
    *(Rule("ios-" + major, "start", r"(?P<ios_banner>Cisco IOS Software, [^,\r\n]++), Version "
           + r"(?P<ios_version>" + major + r"\.[0-9]++[A-Za-z0-9()._-]*+)[^\r\n]*+",
           "record", "start", "", ("ios_banner", "ios_version")) for major in ("12", "15")),
    *(Rule("foreign-" + label, "start", r"(?P<other_banner>" + marker + r")[^\r\n]*+",
           "record", "start", "", ("other_banner",)) for label, marker in (
               ("nxos", r"Cisco Nexus Operating System \(NX-OS\) Software"),
               ("iosxr", "Cisco IOS XR Software"),
           )),
)


def prompt_mode(line: bytes) -> str | None:
    """Recognise only the documented prompt subset; no family/scope inference."""
    for mode, pattern in _PROMPTS:
        if pattern.fullmatch(line):
            return mode
    return None


def classify(raw: bytes) -> IntegrityState:
    """Hazards in one proven response segment; recognised text never proves complete."""
    pieces = raw.split(b"\n")
    for index, piece in enumerate(pieces):
        line = piece.removesuffix(b"\r") if index < len(pieces) - 1 else piece
        view = line.strip(b" \t").replace(b"\xe2\x80\x98", b"'").replace(b"\xe2\x80\x99", b"'")
        if view in ERROR_SIGNATURES or (view.startswith(b'% Ambiguous command: "') and view.endswith(b'"')):
            return IntegrityState.ERROR
    if any(marker in raw for marker in PAGER_SIGNATURES):
        return IntegrityState.PAGING_ARTIFACTS
    if any(prompt_mode(piece) is not None for piece in pieces):
        return IntegrityState.UNVERIFIED_PROMPT
    if not raw:
        return IntegrityState.EMPTY
    return IntegrityState.UNKNOWN_FORMAT


def _reference(raw: bytes, capture: CaptureId, span: ByteSpan | WholeCapture) -> EvidenceRef:
    excerpt = raw[span.start:span.end] if isinstance(span, ByteSpan) else raw
    return EvidenceRef(capture=capture, locator=span, role=EvidenceRole.SUBJECT,
                       excerpt_sha256=sha256(excerpt).hexdigest())


def _unknown(raw: bytes, capture: CaptureId, reason: UnknownReason, detail: str) -> Unknown:
    return Unknown(reason=reason, detail=detail,
                   evidence=(_reference(raw, capture, WholeCapture()),), candidates=(), next_evidence=())


def _fields(parsed: ParseResult, name: str) -> tuple[Captured, ...]:
    return tuple(field for record in parsed.records for key, field in record.fields if key == name)


def _hazard(raw: bytes, capture: CaptureId) -> Unknown | None:
    state = classify(raw)
    if state is IntegrityState.ERROR:
        return _unknown(raw, capture, UnknownReason.CAPTURE_ERROR, "rejected_detection_capture")
    if state is IntegrityState.PAGING_ARTIFACTS:
        return _unknown(raw, capture, UnknownReason.CAPTURE_TRUNCATED, "paged_detection_capture")
    return None


def _version(raw: bytes, capture: CaptureId, parsed: ParseResult) -> Known[str] | Unknown:
    fields = _fields(parsed, "xe_version")
    if not fields:
        return _unknown(raw, capture, UnknownReason.FIELD_NOT_PRINTED, "xe_version_not_printed")
    if len({field.raw for field in fields}) != 1:
        return _unknown(raw, capture, UnknownReason.CONFLICTING_EVIDENCE, "multiple_xe_versions")
    text = fields[0].raw
    if not any(pattern.fullmatch(text.encode("utf-8", "surrogateescape")) for pattern in _VERSION_SHAPES):
        return _unknown(raw, capture, UnknownReason.PARSE_UNSUPPORTED_VARIANT, "xe_version_outside_subset")
    return Known(value=text, basis=Basis.OBSERVED,
                 evidence=tuple(_reference(raw, capture, field.span) for field in fields), raw=text)


def detection_version(raw: bytes, capture: CaptureId) -> Known[str] | Unknown:
    """Keep the printed XE token; a build token is never a release/train attestation."""
    hazard = _hazard(raw, capture)
    if hazard is not None:
        return hazard
    return _version(raw, capture, run_rules(raw, capture, _RULES, ()))


def detect(raw: bytes, capture: CaptureId) -> Known[str] | Unknown:
    """Family primitive only, pending the shared identity/view contract and floors."""
    hazard = _hazard(raw, capture)
    if hazard is not None:
        return hazard
    parsed = run_rules(raw, capture, _RULES, ())
    xe = _fields(parsed, "xe_banner")
    ios = _fields(parsed, "ios_banner")
    other = _fields(parsed, "other_banner")
    if other and (xe or ios):
        return _unknown(raw, capture, UnknownReason.IDENTITY_AMBIGUOUS, "conflicting_family_markers")
    family: Literal["ios", "iosxe"]
    if xe and not other:
        version = _version(raw, capture, parsed)
        if isinstance(version, Unknown):
            return version
        family, fields = "iosxe", xe + _fields(parsed, "xe_version")
    elif ios and not other:
        versions = _fields(parsed, "ios_version")
        if len({field.raw for field in versions}) != 1:
            return _unknown(raw, capture, UnknownReason.CONFLICTING_EVIDENCE, "multiple_ios_versions")
        family, fields = "ios", ios + versions
    else:
        return _unknown(raw, capture, UnknownReason.PLATFORM_UNKNOWN, "iosxe_subset_unclaimed")
    return Known(value=family, basis=Basis.OBSERVED,
                 evidence=tuple(_reference(raw, capture, field.span) for field in fields), raw=fields[0].raw)


_INTERFACE_PREFIXES = (
    (b"GigabitEthernet", "GigabitEthernet"), (b"Gi", "GigabitEthernet"),
    (b"TenGigabitEthernet", "TenGigabitEthernet"), (b"Te", "TenGigabitEthernet"),
    (b"FastEthernet", "FastEthernet"), (b"Fa", "FastEthernet"),
    (b"HundredGigE", "HundredGigE"),
)


def interface_name(raw: bytes) -> str | None:
    """Physical subset only; None is unrecognised, never pass-through or a fact.

    CanonicalInterface/view types have not landed. This helper supplies no speed,
    role, platform/train support or effective-configuration assertion.
    """
    for prefix, canonical in _INTERFACE_PREFIXES:
        if not raw.startswith(prefix):
            continue
        pieces = raw[len(prefix):].split(b".")
        if len(pieces) > 2:
            return None
        path = pieces[0].split(b"/")
        if not 1 <= len(path) <= 4:
            return None
        numbers = path + pieces[1:]
        if any(not part.isdigit() or (len(part) > 1 and part.startswith(b"0")) for part in numbers):
            return None
        return canonical + raw[len(prefix):].decode("ascii")
    return None

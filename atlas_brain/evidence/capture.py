"""CLI capture metadata; classification enums remain owned by the kernel."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval

from .text import TextLine


class Channel(StrEnum):
    CLI = "cli"
    REST = "rest"
    MDM = "mdm"
    FILE = "file"


class ErrorKind(StrEnum):
    INVALID_INPUT = "invalid_input"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"
    UNAUTHORIZED = "unauthorized"
    UNSUPPORTED = "unsupported"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True, kw_only=True)
class Scope:
    node: k.EntityKey
    vrf: str | None
    context: str | None
    vdc: str | None
    tenant: str | None
    afi: str | None
    instance: str | None
    plane: Literal["exec", "admin", "controller"]

    def __post_init__(self) -> None:
        k.text_fields(self.node)
        k.require(self.plane in ("exec", "admin", "controller"), "invalid_plane")
        for value in (self.vrf, self.context, self.vdc, self.tenant, self.afi, self.instance):
            if value is not None:
                k.text_fields(value)


def classify_cli(raw: bytes, succeeded: str, prompt_verified: bool) -> k.IntegrityState:
    if not prompt_verified or succeeded != "yes":
        return k.IntegrityState.UNVERIFIED_PROMPT
    return k.IntegrityState.EMPTY if not raw else k.IntegrityState.UNKNOWN_FORMAT


@dataclass(frozen=True, slots=True, kw_only=True)
class Capture:
    id: k.CaptureId
    source: k.EntityKey
    channel: Channel
    operation: str | None
    rendered: str
    scope: Scope
    collected_utc: TimeInterval | k.Unknown
    codec: str
    integrity: k.IntegrityState
    error: ErrorKind | None
    integrity_evidence: tuple[k.EvidenceRef, ...]
    read_scope: k.ReadScope
    read_scope_evidence: tuple[k.Evidence, ...]
    view: k.ViewConsistency
    envelope: None  # Version-one folder transport supports CLI only.
    raw: bytes
    lines: tuple[TextLine, ...]

    def __post_init__(self) -> None:
        k.text_fields(self.id, self.source, self.rendered, self.codec)
        k.require(type(self.scope) is Scope and self.scope.node == self.source, "scope_source_mismatch")
        k.require(type(self.channel) is Channel and self.channel is Channel.CLI and self.envelope is None, "cli_transport_required")
        k.require(type(self.integrity) is k.IntegrityState and type(self.read_scope) is k.ReadScope
                  and type(self.view) is k.ViewConsistency, "invalid_capture_classification")
        k.require(type(self.raw) is bytes, "immutable_capture_bytes_required")
        k.require(self.operation is None or (type(self.operation) is str and bool(self.operation)), "invalid_operation")
        k.require(self.error is None or type(self.error) is ErrorKind, "invalid_error_kind")
        k.evidence_tuple(self.integrity_evidence, nonempty=True)
        for ref in self.integrity_evidence:
            k.require(type(ref) is k.EvidenceRef and ref.capture == self.id, "capture_witness_mismatch")
            if type(ref.locator) is k.ByteSpan:
                k.require(ref.locator.end <= len(self.raw), "capture_witness_out_of_bounds")
                excerpt = self.raw[ref.locator.start:ref.locator.end]
            elif type(ref.locator) is k.WholeCapture:
                excerpt = self.raw
            else:
                raise ValueError("cli_witness_locator_required")
            k.require(ref.excerpt_sha256 == sha256(excerpt).hexdigest(), "capture_witness_mismatch")
        k.evidence_tuple(self.read_scope_evidence, nonempty=self.read_scope is not k.ReadScope.UNKNOWN)
        k.require(type(self.collected_utc) in (TimeInterval, k.Unknown), "invalid_collector_time")
        if isinstance(self.collected_utc, TimeInterval):
            k.require(self.collected_utc.bound is BoundSource.COLLECTOR_RECORDED
                      and self.collected_utc.clock.startswith("collector:"), "recorded_collector_time_required")

    @property
    def bytes_sha256(self) -> str:
        return sha256(self.raw).hexdigest()

    @property
    def byte_len(self) -> int:
        return len(self.raw)


def unrecorded_time(witness: k.EvidenceRef) -> k.Unknown:
    return k.Unknown(reason=k.UnknownReason.AS_OF_MISSING, detail="no_collector_time",
                     evidence=(witness,), candidates=(), next_evidence=())

"""Conservative CLI intake records; platform adapters refine structural states."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.kernel import states as k

from .text import TextLine


def classify_cli(raw: bytes, succeeded: str, prompt_verified: bool) -> k.IntegrityState:
    if not prompt_verified or succeeded != "yes":
        return k.IntegrityState.UNVERIFIED_PROMPT
    return k.IntegrityState.EMPTY if not raw else k.IntegrityState.UNKNOWN_FORMAT


@dataclass(frozen=True, slots=True)
class Capture:
    id: k.CaptureId
    source: k.EntityKey
    operation: str
    rendered: str
    codec: str
    raw: bytes
    integrity: k.IntegrityState
    lines: tuple[TextLine, ...]
    read_scope: k.ReadScope
    view: k.ViewConsistency
    collected_utc: k.Unknown

    @property
    def bytes_sha256(self) -> str:
        return sha256(self.raw).hexdigest()

    @property
    def byte_len(self) -> int:
        return len(self.raw)


def unrecorded_time() -> k.Unknown:
    return k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="no_collector_time",
                   evidence=(), candidates=(), next_evidence=())

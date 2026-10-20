"""Conservative CLI intake records; platform adapters refine structural states."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from atlas_brain.kernel.states import CaptureId, EntityKey, Unknown, UnknownReason

from .text import TextLine


class IntegrityState(StrEnum):
    COMPLETE = "complete"
    EMPTY = "empty"
    ABSENCE_BANNER = "absence_banner"
    ERROR = "error"
    TRUNCATED = "truncated"
    PAGING_ARTIFACTS = "paging_artifacts"
    UNVERIFIED_PROMPT = "unverified_prompt"
    UNKNOWN_FORMAT = "unknown_format"


def classify_cli(raw: bytes, succeeded: str, prompt_verified: bool) -> IntegrityState:
    if not prompt_verified or succeeded != "yes":
        return IntegrityState.UNVERIFIED_PROMPT
    return IntegrityState.EMPTY if not raw else IntegrityState.UNKNOWN_FORMAT


@dataclass(frozen=True, slots=True)
class Capture:
    id: CaptureId
    source: EntityKey
    operation: str
    rendered: str
    codec: str
    raw: bytes
    integrity: IntegrityState
    lines: tuple[TextLine, ...]
    read_scope: str
    collected_utc: Unknown

    @property
    def bytes_sha256(self) -> str:
        return sha256(self.raw).hexdigest()

    @property
    def byte_len(self) -> int:
        return len(self.raw)


def unrecorded_time() -> Unknown:
    return Unknown(reason=UnknownReason.NOT_COLLECTED, detail="no_collector_time",
                   evidence=(), candidates=(), next_evidence=())

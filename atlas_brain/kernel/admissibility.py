"""Single capture-admissibility table (architecture 1.4.3).

Registration flags are outputs of a validated operation registry, never inferred
from an empty payload. Printed partial records require their own complete spans.
"""
from dataclasses import dataclass
from enum import StrEnum

from .states import UnknownReason, require


class IntegrityState(StrEnum):
    COMPLETE = 'complete'
    EMPTY = 'empty'
    ABSENCE_BANNER = 'absence_banner'
    ERROR = 'error'
    TRUNCATED = 'truncated'
    PAGING_ARTIFACTS = 'paging_artifacts'
    UNVERIFIED_PROMPT = 'unverified_prompt'
    UNKNOWN_FORMAT = 'unknown_format'


class ReadScope(StrEnum):
    FULL_EVIDENCED = 'full_evidenced'
    NOT_SCOPE_SENSITIVE = 'not_scope_sensitive'
    LIMITED = 'limited'
    UNKNOWN = 'unknown'


class ViewConsistency(StrEnum):
    ATOMIC = 'atomic'
    SINGLE_RESPONSE = 'single_response'
    NON_ATOMIC = 'non_atomic'
    CACHED = 'cached'
    UNKNOWN = 'unknown'


@dataclass(frozen=True, slots=True, kw_only=True)
class Admission:
    problem: bool
    ok: bool
    population: bool
    reason: UnknownReason | None


# integrity, printed-record problem, printed-record ok, population, refusal
ROWS: tuple[tuple[IntegrityState, bool, bool, bool, UnknownReason | None], ...] = (
    (IntegrityState.COMPLETE, True, True, True, None),
    (IntegrityState.EMPTY, False, False, True, None),
    (IntegrityState.ABSENCE_BANNER, False, False, True, None),
    (IntegrityState.TRUNCATED, True, False, False, UnknownReason.CAPTURE_TRUNCATED),
    (IntegrityState.PAGING_ARTIFACTS, True, False, False, UnknownReason.CAPTURE_TRUNCATED),
    (IntegrityState.UNVERIFIED_PROMPT, True, False, False, UnknownReason.CAPTURE_TRUNCATED),
    (IntegrityState.ERROR, False, False, False, UnknownReason.CAPTURE_ERROR),
    (IntegrityState.UNKNOWN_FORMAT, False, False, False, UnknownReason.PARSE_UNSUPPORTED_VARIANT),
)


def admissibility(integrity: IntegrityState, read_scope: ReadScope, view: ViewConsistency, *,
                  empty_registered: bool, banner_registered: bool, cache_age_evidenced: bool) -> Admission:
    require(type(integrity) is IntegrityState and type(read_scope) is ReadScope and type(view) is ViewConsistency, 'invalid_classification')
    require(all(type(f) is bool for f in (empty_registered, banner_registered, cache_age_evidenced)), 'invalid_registration_flags')
    row = next(r for r in ROWS if r[0] is integrity)
    _, problem, ok, population, reason = row
    if population:
        if (integrity is IntegrityState.EMPTY and not empty_registered) or (integrity is IntegrityState.ABSENCE_BANNER and not banner_registered):
            population, reason = False, UnknownReason.EMPTY_UNREGISTERED
        elif read_scope not in (ReadScope.FULL_EVIDENCED, ReadScope.NOT_SCOPE_SENSITIVE):
            population, reason = False, UnknownReason.SCOPE_LIMITED
        elif view not in (ViewConsistency.ATOMIC, ViewConsistency.SINGLE_RESPONSE) and not (view is ViewConsistency.CACHED and cache_age_evidenced):
            population, reason = False, UnknownReason.NON_ATOMIC_VIEW
    return Admission(problem=problem, ok=ok, population=population, reason=reason)

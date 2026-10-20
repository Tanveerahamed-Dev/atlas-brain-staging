from itertools import product

import pytest

from atlas_brain.kernel.admissibility import admissibility
from atlas_brain.kernel.states import IntegrityState, ReadScope, UnknownReason, ViewConsistency


def decide(integrity, scope, view, registered=True):
    return admissibility(integrity, scope, view, empty_registered=registered,
                         banner_registered=registered, cache_age_evidenced=True)


@pytest.mark.parametrize('integrity,scope,view', product(IntegrityState, ReadScope, ViewConsistency))
def test_every_cli_admissibility_row(integrity, scope, view):
    result = decide(integrity, scope, view)
    population = integrity in (IntegrityState.COMPLETE, IntegrityState.EMPTY, IntegrityState.ABSENCE_BANNER)
    population &= scope in (ReadScope.FULL_EVIDENCED, ReadScope.NOT_SCOPE_SENSITIVE)
    population &= view in (ViewConsistency.ATOMIC, ViewConsistency.SINGLE_RESPONSE, ViewConsistency.CACHED)
    assert result.population is population
    assert result.ok is (integrity is IntegrityState.COMPLETE)
    assert result.problem is (integrity in (IntegrityState.COMPLETE, IntegrityState.TRUNCATED,
                                          IntegrityState.PAGING_ARTIFACTS, IntegrityState.UNVERIFIED_PROMPT))


def test_registered_empty_and_failed_empty_are_distinct():
    args = ReadScope.FULL_EVIDENCED, ViewConsistency.SINGLE_RESPONSE
    assert decide(IntegrityState.EMPTY, *args).population
    assert decide(IntegrityState.EMPTY, *args, registered=False).reason is UnknownReason.EMPTY_UNREGISTERED
    assert not decide(IntegrityState.ERROR, *args).population
    assert not decide(IntegrityState.ERROR, *args).ok


def test_cached_population_needs_age_evidence():
    result = admissibility(IntegrityState.COMPLETE, ReadScope.FULL_EVIDENCED,
                           ViewConsistency.CACHED, empty_registered=True,
                           banner_registered=True, cache_age_evidenced=False)
    assert not result.population
    assert result.reason is UnknownReason.NON_ATOMIC_VIEW


def test_string_enum_and_truthy_flags_are_refused():
    with pytest.raises(ValueError):
        decide('complete', ReadScope.FULL_EVIDENCED, ViewConsistency.SINGLE_RESPONSE)
    with pytest.raises(ValueError):
        decide(IntegrityState.EMPTY, ReadScope.FULL_EVIDENCED,
               ViewConsistency.SINGLE_RESPONSE, registered='yes')


def test_admission_record_rejects_truthy_non_booleans():
    from atlas_brain.kernel.admissibility import Admission

    with pytest.raises(ValueError):
        Admission(problem='yes', ok=True, population=True, reason=None)

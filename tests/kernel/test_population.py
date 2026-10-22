from dataclasses import replace

import pytest

from atlas_brain.kernel.population import ExpectedSet, coverage
from atlas_brain.kernel.states import (
    CaptureId,
    EvidenceRef,
    EvidenceRole,
    NAReason,
    NotApplicable,
    UnknownReason,
    WholeCapture,
)


def witness():
    return EvidenceRef(capture=CaptureId('cap:synthetic'), locator=WholeCapture(),
                       role=EvidenceRole.ABSENCE_WITNESS, excerpt_sha256='a' * 64)


def population(candidates=(), members=(), exclusions=(), unresolved=(), closed=True):
    return ExpectedSet(population='example.subjects', candidates=candidates,
                       members=members, member_evidence=tuple((m, (witness(),)) for m in members),
                       exclusions=exclusions, unresolved=unresolved, closed=closed,
                       lower_bound_nodes=() if closed else ('node:a',), closure_evidence=(witness(),) if closed else ())


@pytest.mark.parametrize('factory', [
    lambda: population(candidates=('node:a',)),
    lambda: population(candidates=('node:a',), members=('node:a',),
                       unresolved=(('node:a', UnknownReason.NOT_COLLECTED),)),
    lambda: population(candidates=('node:a',), exclusions=(('node:a', NAReason.ROLE_EXCLUDES, ()),)),
    lambda: population(candidates=('node:b', 'node:a'), members=('node:b', 'node:a')),
])
def test_planted_partition_violations(factory):
    with pytest.raises(ValueError):
        factory()


def test_empty_closed_population_never_becomes_ok():
    summary = coverage(population())
    assert summary.expected == 0
    assert summary.state == 'none_expected'
    assert summary.closure_evidence
    opened = coverage(population(closed=False))
    assert opened.state == 'unknown'
    assert opened.reason is UnknownReason.DENOMINATOR_OPEN


def test_all_three_parts_partition_the_candidates():
    summary = coverage(population(candidates=('node:a', 'node:b', 'node:c'), members=('node:a',),
                                 exclusions=(('node:b', NAReason.ROLE_EXCLUDES, (witness(),)),),
                                 unresolved=(('node:c', UnknownReason.NOT_COLLECTED),)))
    assert (summary.expected, summary.excluded, summary.unresolved) == (1, 1, 1)


def test_feature_absence_exclusion_requires_the_canonical_absence_witness():
    subject_span = replace(witness(), role=EvidenceRole.SUBJECT)
    with pytest.raises(ValueError):
        NotApplicable(reason=NAReason.FEATURE_NOT_CONFIGURED, evidence=(subject_span,))
    with pytest.raises(ValueError):
        population(candidates=('node:a',), exclusions=(
            ('node:a', NAReason.FEATURE_NOT_CONFIGURED, (subject_span,)),))


@pytest.mark.parametrize('reason', tuple(NAReason))
@pytest.mark.parametrize('role', tuple(EvidenceRole))
def test_exclusions_preserve_every_canonical_not_applicable_evidence_rule(reason, role):
    proof = (replace(witness(), role=role),)
    exclusion = ('node:a', reason, proof)
    try:
        NotApplicable(reason=reason, evidence=proof)
    except ValueError:
        with pytest.raises(ValueError):
            population(candidates=('node:a',), exclusions=(exclusion,))
    else:
        assert population(candidates=('node:a',), exclusions=(exclusion,)).exclusions == (exclusion,)

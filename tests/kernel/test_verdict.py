from dataclasses import replace

import pytest

from atlas_brain.kernel.admissibility import Admission
from atlas_brain.kernel.population import ExpectedSet
from atlas_brain.kernel.states import (
    Basis, ByteSpan, CaptureId, EntityKey, EvidenceRef, EvidenceRole, Known,
    Unknown, UnknownReason,
)
from atlas_brain.kernel.verdict import CheckInput, CheckSpec, CheckState, Decision, VerdictBasis, verdict


def evidence():
    return EvidenceRef(capture=CaptureId('cap:synthetic'), locator=ByteSpan(start=0, end=1),
                       role=EvidenceRole.SUBJECT, excerpt_sha256='a' * 64)


def spec():
    return CheckSpec(id='example.check', population='example.population',
                     inputs=(CheckInput(ref='example.fact', role='required', accepts_absent=False),),
                     basis=VerdictBasis.OPERATIONAL_STATE, ok_bases=frozenset({Basis.OBSERVED}),
                     problem_from_subset=frozenset({'broken'}), reasons=(('broken', CheckState.PROBLEM), ('healthy', CheckState.OK)),
                     severity='major', aggregates=())


def run(fact, state=CheckState.OK, reason='healthy', policy=None, closed=True, aggregates=()):
    expected = ExpectedSet(population='example.population', candidates=('node:a',), members=('node:a',),
                           member_evidence=(('node:a', (evidence(),)),), exclusions=(), unresolved=(),
                           closed=closed, lower_bound_nodes=(), closure_evidence=(evidence(),))
    return verdict(spec=policy or spec(), subject=EntityKey('node:a'), expected=expected,
                   inputs=(('example.fact', fact),), aggregates=aggregates,
                   admissions=((CaptureId('cap:synthetic'), Admission(problem=True, ok=True, population=True, reason=None)),),
                   predicate=lambda facts: Decision(state=state, reason=reason, proofs=tuple(facts), params=()))


def test_only_not_collected_can_never_be_ok():
    missing = Unknown(reason=UnknownReason.NOT_COLLECTED, detail='never_attempted',
                      evidence=(), candidates=(), next_evidence=())
    assert run(missing).state is CheckState.UNKNOWN


def test_positive_observation_can_be_ok_and_wrong_reason_state_is_refused():
    fact = Known(value=1, basis=Basis.OBSERVED, evidence=(evidence(),), raw=None)
    assert run(fact).state is CheckState.OK
    bad = run(fact, CheckState.PROBLEM, 'healthy')
    assert bad.state is CheckState.UNKNOWN
    assert bad.reason == 'analysis_failed'


def test_open_denominator_and_disallowed_basis_cannot_be_ok():
    fact = Known(value=1, basis=Basis.OBSERVED, evidence=(evidence(),), raw=None)
    assert run(fact, closed=False).reason == 'denominator_open'
    assert run(replace(fact, basis=Basis.DECLARED)).state is CheckState.UNKNOWN


def test_aggregate_unknown_and_unclaimed_member_block_ok():
    fact = Known(value=1, basis=Basis.OBSERVED, evidence=(evidence(),), raw=None)
    policy = replace(spec(), aggregates=('routing_protocol',))
    unclaimed = Known(value=('unclaimed',), basis=Basis.OBSERVED, evidence=(evidence(),), raw=None)
    assert run(fact, policy=policy, aggregates=(('routing_protocol', unclaimed),)).reason == 'unmodelled_present'
    missing = Unknown(reason=UnknownReason.NOT_COLLECTED, detail=None, evidence=(), candidates=(), next_evidence=())
    assert run(fact, policy=policy, aggregates=(('routing_protocol', missing),)).state is CheckState.UNKNOWN


def test_reason_binding_registration_is_closed():
    with pytest.raises(ValueError):
        replace(spec(), reasons=(('same', CheckState.OK), ('same', CheckState.PROBLEM)))

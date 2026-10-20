"""Minimum positive-proof verdict kernel; no pack constructs a result.

This stage accepts direct capture proofs. Derived provenance, temporal alignment
and operation rendering must be admitted by their owning boundaries before use.
Unsupported proof paths fail closed, rather than borrowing an observation basis.
"""
from collections.abc import Callable, Mapping
from dataclasses import InitVar, dataclass
from enum import StrEnum
from typing import Literal, assert_never, final

from .admissibility import Admission
from .population import ExpectedSet
from .states import (
    Absent, Basis, ByteSpan, CaptureId, EntityKey, Evidence, EvidenceNeed,
    EvidenceRef, EvidenceRole, Fact, Known, NotApplicable, Unknown, UnknownReason,
    evidence_tuple, require,
)

type Scalar = str | int | bool | None
_PERMIT = object()


class CheckState(StrEnum):
    PROBLEM = 'problem'
    OK = 'ok'
    UNKNOWN = 'unknown'
    NOT_APPLICABLE = 'not_applicable'


class VerdictBasis(StrEnum):
    CONFIG_PRESENCE = 'config-presence'
    OPERATIONAL_STATE = 'operational-state'
    EXPECTED_VS_OBSERVED = 'expected-vs-observed'
    CROSS_DEVICE = 'cross-device-correlated'


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckInput:
    ref: str
    role: Literal['required', 'witness', 'gate']
    accepts_absent: bool

    def __post_init__(self) -> None:
        require(bool(self.ref) and self.role in ('required', 'witness', 'gate') and type(self.accepts_absent) is bool, 'invalid_check_input')


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckSpec:
    id: str
    population: str
    inputs: tuple[CheckInput, ...]
    basis: VerdictBasis
    ok_bases: frozenset[Basis]
    problem_from_subset: frozenset[str]
    reasons: tuple[tuple[str, CheckState], ...]
    severity: str
    aggregates: tuple[str, ...]

    def __post_init__(self) -> None:
        require(bool(self.id) and bool(self.population) and bool(self.severity), 'missing_check_identity')
        require(type(self.basis) is VerdictBasis and type(self.inputs) is tuple, 'invalid_check_spec')
        require(len({i.ref for i in self.inputs}) == len(self.inputs) and any(i.role == 'required' for i in self.inputs), 'invalid_check_inputs')
        require(sum(i.role == 'gate' for i in self.inputs) <= 1, 'multiple_gates')
        require(type(self.ok_bases) is frozenset and all(type(b) is Basis for b in sorted(self.ok_bases)), 'invalid_ok_bases')
        require(not self.ok_bases.intersection((Basis.DECLARED, Basis.INFERRED, Basis.REGISTRY)), 'non_observational_ok_basis')
        require(self.reasons == tuple(sorted(self.reasons)) and len(dict(self.reasons)) == len(self.reasons), 'invalid_reason_bindings')
        require(all(type(s) is CheckState and s in (CheckState.OK, CheckState.PROBLEM) and r not in UnknownReason for r, s in self.reasons), 'invalid_reason_state')
        require(self.problem_from_subset <= {r for r, s in self.reasons if s is CheckState.PROBLEM}, 'invalid_subset_reasons')


@dataclass(frozen=True, slots=True, kw_only=True)
class Decision:
    state: CheckState
    reason: str
    proofs: tuple[str, ...]
    params: tuple[tuple[str, Scalar], ...]

    def __post_init__(self) -> None:
        require(type(self.state) is CheckState, 'invalid_decision_state')
        require(self.proofs == tuple(sorted(set(self.proofs))), 'invalid_proof_keys')
        require(tuple(k for k, _ in self.params) == tuple(sorted({k for k, _ in self.params})), 'invalid_params')
        require(all(type(v) in (str, int, bool, type(None)) for _, v in self.params), 'invalid_param_value')


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class CheckResult:
    check: str
    subject: EntityKey
    state: CheckState
    severity: str | None
    basis: VerdictBasis
    reason: str
    params: tuple[tuple[str, Scalar], ...]
    evidence: tuple[Evidence, ...]
    counter_evidence: tuple[Evidence, ...]
    input_bases: tuple[Basis, ...]
    next_evidence: tuple[EvidenceNeed, ...]
    confirm_on_device: tuple[()]
    permit: InitVar[object]

    def __post_init__(self, permit: object) -> None:
        require(permit is _PERMIT, 'verdict_constructor_only')
        evidence_tuple(self.evidence, nonempty=self.state is not CheckState.UNKNOWN)

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError('closed_check_result')


def verdict(*, spec: CheckSpec, subject: EntityKey, expected: ExpectedSet,
            inputs: tuple[tuple[str, Fact[object]], ...], aggregates: tuple[tuple[str, Fact[object]], ...],
            admissions: tuple[tuple[CaptureId, Admission], ...],
            predicate: Callable[[Mapping[str, Fact[object]]], Decision]) -> CheckResult:
    require(expected.population == spec.population and subject in expected.members, 'subject_outside_population')
    values = dict(inputs)
    require(len(values) == len(inputs) and set(values) == {i.ref for i in spec.inputs}, 'input_binding_mismatch')
    admitted = dict(admissions)
    require(len(admitted) == len(admissions), 'duplicate_capture_admission')
    bases: set[Basis] = set()
    evidence: list[Evidence] = []
    needs: list[EvidenceNeed] = []

    def result(state: CheckState, reason: str, params: tuple[tuple[str, Scalar], ...] = ()) -> CheckResult:
        unique = tuple(dict.fromkeys(evidence))
        counter = tuple(e for e in unique if type(e) is EvidenceRef and e.role is EvidenceRole.COUNTER_EVIDENCE)
        return CheckResult(check=spec.id, subject=subject, state=state,
                           severity=spec.severity if state is CheckState.PROBLEM else None,
                           basis=spec.basis, reason=reason, params=params, evidence=unique,
                           counter_evidence=counter, input_bases=tuple(sorted(bases)),
                           next_evidence=tuple(dict.fromkeys(needs)), confirm_on_device=(), permit=_PERMIT)

    def supported(refs: tuple[Evidence, ...], claim: str) -> bool:
        if not refs:
            return False
        for ref in refs:
            if type(ref) is not EvidenceRef or ref.capture not in admitted:
                return False
            admission = admitted[ref.capture]
            if claim == 'ok' and not admission.ok:
                return False
            if claim == 'population' and not admission.population:
                return False
            if claim == 'problem' and (not admission.problem or
                    (not admission.ok and (type(ref.locator) is not ByteSpan or ref.locator.start == ref.locator.end))):
                return False
        return True

    resolved: dict[str, Fact[object]] = {}
    blockers: list[UnknownReason] = []
    gate: NotApplicable | Unknown | None = None
    for item in spec.inputs:
        fact = values[item.ref]
        evidence.extend(fact.evidence)
        match fact:
            case Known():
                bases.add(fact.basis)
                if item.role != 'witness':
                    resolved[item.ref] = fact
            case Absent():
                bases.add(fact.basis)
                if item.role != 'witness':
                    if item.accepts_absent and (fact.basis is not Basis.CONFIGURED or spec.basis is VerdictBasis.CONFIG_PRESENCE) and supported(fact.evidence, 'population'):
                        resolved[item.ref] = fact
                    else:
                        blockers.append(UnknownReason.DEFAULT_UNKNOWN)
            case Unknown():
                needs.extend(fact.next_evidence)
                if item.role != 'witness':
                    blockers.append(fact.reason)
                    if item.role == 'gate':
                        gate = fact
            case NotApplicable():
                if item.role == 'gate':
                    gate = fact
                elif item.role != 'witness':
                    blockers.append(UnknownReason.ANALYSIS_GAP)
            case _ as impossible:
                assert_never(impossible)
    if gate is not None:
        if type(gate) is Unknown:
            return result(CheckState.UNKNOWN, gate.reason)
        if supported(gate.evidence, 'population'):
            return result(CheckState.NOT_APPLICABLE, gate.reason)
        return result(CheckState.UNKNOWN, UnknownReason.ANALYSIS_GAP)
    decision = predicate(resolved)
    bindings = dict(spec.reasons)
    if decision.reason not in bindings or bindings[decision.reason] is not decision.state:
        return result(CheckState.UNKNOWN, UnknownReason.ANALYSIS_FAILED)
    if not decision.proofs or any(p not in resolved for p in decision.proofs):
        return result(CheckState.UNKNOWN, blockers[0] if blockers else UnknownReason.ANALYSIS_GAP)
    deciding = tuple(resolved[p] for p in decision.proofs)
    if decision.state is CheckState.PROBLEM:
        if (not blockers or decision.reason in spec.problem_from_subset) and all(supported(f.evidence, 'problem') for f in deciding):
            return result(CheckState.PROBLEM, decision.reason, decision.params)
        return result(CheckState.UNKNOWN, blockers[0] if blockers else UnknownReason.ANALYSIS_GAP)
    if blockers:
        return result(CheckState.UNKNOWN, blockers[0])
    if not expected.closed or expected.unresolved:
        return result(CheckState.UNKNOWN, UnknownReason.DENOMINATOR_OPEN)
    if set(decision.proofs) != set(resolved) or not all(type(f) in (Known, Absent) and f.basis in spec.ok_bases and supported(f.evidence, 'ok') for f in deciding):
        return result(CheckState.UNKNOWN, UnknownReason.ANALYSIS_GAP)
    census = dict(aggregates)
    for klass in spec.aggregates:
        if klass not in census:
            return result(CheckState.UNKNOWN, UnknownReason.ANALYSIS_GAP)
        fact = census[klass]
        evidence.extend(fact.evidence)
        if type(fact) is Unknown:
            needs.extend(fact.next_evidence)
            return result(CheckState.UNKNOWN, fact.reason)
        if type(fact) is not Known or fact.value != ():
            return result(CheckState.UNKNOWN, UnknownReason.UNMODELLED_PRESENT)
        if not supported(fact.evidence, 'population'):
            return result(CheckState.UNKNOWN, UnknownReason.SCOPE_LIMITED)
    if spec.basis is VerdictBasis.CROSS_DEVICE:
        return result(CheckState.UNKNOWN, UnknownReason.NOT_OBSERVABLE)
    return result(CheckState.OK, decision.reason, decision.params)

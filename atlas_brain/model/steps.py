"""Deterministic producer graph; entity readers wait for every mention (S1 1.9.2)."""
from dataclasses import dataclass
from heapq import heapify, heappop, heappush
from typing import Literal

from atlas_brain.kernel.states import require, text_fields


@dataclass(frozen=True, slots=True, kw_only=True)
class StepSpec:
    id: str
    kind: Literal['parse_build', 'derive', 'population', 'check']
    scope: Literal['device', 'estate']
    reads_operations: tuple[str, ...]
    reads_config: tuple[str, ...]
    consumes: tuple[str, ...]
    produces: tuple[str, ...]
    mentions: tuple[str, ...]
    evaluator: str

    def __post_init__(self) -> None:
        text_fields(self.id, self.evaluator)
        require(self.id.count('/') == 1 and all(self.id.split('/')), 'invalid_step_id')
        require(self.evaluator.startswith(self.id.split('/')[0] + '.'), 'evaluator_outside_owner')
        require(self.kind in ('parse_build', 'derive', 'population', 'check') and self.scope in ('device', 'estate'), 'invalid_step_kind_or_scope')
        for values in (self.reads_operations, self.reads_config, self.consumes, self.produces, self.mentions):
            require(type(values) is tuple and values == tuple(sorted(set(values))), 'invalid_step_declarations')
            text_fields(*values)
        require(self.kind == 'parse_build' or not (self.reads_operations or self.reads_config), 'parse_reads_outside_parse_build')


def order_steps(steps: tuple[StepSpec, ...]) -> tuple[StepSpec, ...]:
    require(type(steps) is tuple and all(type(s) is StepSpec for s in steps), 'invalid_steps')
    by_id = {s.id: s for s in steps}
    require(len(by_id) == len(steps), 'duplicate_step')
    producers: dict[str, set[str]] = {}
    for step in sorted(steps, key=lambda s: s.id):
        for item in step.produces:
            require(item not in producers, 'duplicate_producer')
            producers[item] = {step.id}
    for step in sorted(steps, key=lambda s: s.id):
        for kind in step.mentions:
            item = 'entities:' + kind
            require(item in producers, 'unowned_entity_kind')
            producers[item].add(step.id)
    needs: dict[str, set[str]] = {}
    for step in sorted(steps, key=lambda s: s.id):
        dependencies: set[str] = set()
        for item in step.consumes:
            require(item in producers, 'missing_producer')
            dependencies.update(producers[item])
        require(step.scope == 'estate' or all(by_id[d].scope == 'device' for d in sorted(dependencies)), 'device_reads_estate')
        needs[step.id] = dependencies
    pending = dict(by_id)
    result: list[StepSpec] = []
    dependents: dict[str, set[str]] = {key: set() for key in by_id}
    for key in sorted(needs):
        for dependency in sorted(needs[key]):
            dependents[dependency].add(key)
    ready = [key for key in sorted(pending) if not needs[key]]
    heapify(ready)
    while ready:
        key = heappop(ready)
        result.append(pending.pop(key))
        for dependent in sorted(dependents[key]):
            needs[dependent].remove(key)
            if not needs[dependent]:
                heappush(ready, dependent)
    if pending:
        def cyclic(node: str) -> bool:
            seen: set[str] = set()
            frontier = sorted(needs[node])
            while frontier:
                current = frontier.pop()
                if current == node:
                    return True
                if current not in seen:
                    seen.add(current)
                    frontier.extend(sorted(needs[current]))
            return False
        members = tuple(key for key in sorted(pending) if cyclic(key))
        raise ValueError('cyclic_steps:' + ','.join(members))
    return tuple(result)

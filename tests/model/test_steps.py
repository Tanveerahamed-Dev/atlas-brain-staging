from dataclasses import replace

import pytest

from atlas_brain.model.steps import StepSpec, order_steps


def step(name, consumes=(), produces=(), mentions=()):
    return StepSpec(id='example/' + name, kind='derive', scope='device',
                    reads_operations=(), reads_config=(), consumes=consumes,
                    produces=produces, mentions=mentions, evaluator='example.steps.' + name)


def test_cyclic_registration_is_refused():
    with pytest.raises(ValueError, match='cyclic_steps'):
        order_steps((step('a', ('example.b',), ('example.a',)),
                     step('b', ('example.a',), ('example.b',))))


@pytest.mark.parametrize('steps', [
    (step('a'), step('a')),
    (step('a', produces=('example.fact',)), step('b', produces=('example.fact',))),
    (step('a', consumes=('example.missing',)),),
])
def test_duplicate_steps_outputs_and_missing_producer_are_refused(steps):
    with pytest.raises(ValueError):
        order_steps(steps)


def test_independent_ties_and_input_order_are_deterministic():
    steps = (step('z', produces=('example.z',)), step('a', produces=('example.a',)),
             step('join', consumes=('example.a', 'example.z'), produces=('example.join',)))
    assert order_steps(steps) == order_steps(tuple(reversed(steps)))
    assert tuple(s.id for s in order_steps(steps)) == ('example/a', 'example/z', 'example/join')


def test_every_entity_mention_precedes_complete_entity_consumption():
    steps = (step('owner', produces=('entities:interface',)),
             step('mention', mentions=('interface',)),
             step('consumer', consumes=('entities:interface',)))
    result = tuple(s.id for s in order_steps(steps))
    assert result.index('example.consumer'.replace('.', '/')) > result.index('example/owner')
    assert result.index('example/consumer') > result.index('example/mention')


def test_duplicate_declarations_and_parse_reads_on_derive_are_refused():
    with pytest.raises(ValueError):
        step('a', consumes=('example.fact', 'example.fact'))
    with pytest.raises(ValueError):
        replace(step('a'), reads_operations=('example.read',))

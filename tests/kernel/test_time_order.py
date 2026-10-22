from itertools import permutations

import pytest

from atlas_brain.kernel.states import CaptureId
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.kernel.time_order import collector_before, settled_captures


def interval(start, end, clock='collector:a', bound=BoundSource.COLLECTOR_RECORDED):
    return TimeInterval(earliest=start, latest=end, clock=clock, bound=bound)


@pytest.mark.parametrize('first,second,expected', [
    (interval(0, 1), interval(2, 3), True),
    (interval(0, 1), interval(1, 3), False),
    (interval(0, 2), interval(1, 3), False),
    (interval(2, 3), interval(0, 1), False),
    (interval(0, 1), interval(2, 3, 'collector:b'), False),
    (interval(0, 1, bound=BoundSource.PER_EVENT_QUALITY), interval(2, 3), False),
    (interval(None, None, bound=BoundSource.UNBOUNDED), interval(2, 3), False),
    (None, interval(2, 3), False),
    (interval(0, 1), None, False),
    (interval(0, 1, 'node:sw-a/epoch:one'), interval(2, 3, 'node:sw-a/epoch:one'), False),
])
def test_only_strict_same_collector_order_is_proven(first, second, expected):
    assert collector_before(first, second) is expected


def test_unordered_sample_is_never_outvoted_by_a_later_timed_sample():
    samples = ((CaptureId('cap:a'), interval(0, 1)),
               (CaptureId('cap:b'), interval(2, 3)),
               (CaptureId('cap:c'), None))
    for ordering in permutations(samples):
        assert settled_captures(ordering) == ('cap:b', 'cap:c')


def test_overlapping_or_different_clock_samples_both_remain_settled():
    for other in (interval(1, 3), interval(4, 5, 'collector:b')):
        assert settled_captures(((CaptureId('cap:a'), interval(0, 2)),
                                 (CaptureId('cap:b'), other))) == ('cap:a', 'cap:b')


@pytest.mark.parametrize('samples', [
    ((CaptureId('cap:a'), None), (CaptureId('cap:a'), interval(1, 2))),
    ((CaptureId(''), None),),
])
def test_duplicate_or_missing_capture_identity_is_refused(samples):
    with pytest.raises(ValueError):
        settled_captures(samples)


def test_no_samples_does_not_manufacture_a_settled_capture():
    assert settled_captures(()) == ()


def continuous(samples, *, target=b'"EXSTART"', separation_s=120):
    from atlas_brain.kernel import time_order
    prove = getattr(time_order, 'continuous_collector_pairs', None)
    assert prove is not None
    return prove(samples, target=target, minimum_separation_s=separation_s)


def row(capture, start, end=None, value=b'"EXSTART"', clock='collector:a'):
    observed = None if start is None else interval(start, start if end is None else end, clock)
    return (CaptureId(capture), observed, value)


@pytest.mark.parametrize('later_us,expected', [(119_999_999, ()), (120_000_000, (('cap:z', 'cap:a'),))])
def test_duration_converts_seconds_to_microseconds_without_rounding(later_us, expected):
    assert continuous((row('cap:z', 0), row('cap:a', later_us))) == expected


def test_a_different_ordered_state_breaks_the_old_transient_run():
    samples = (row('cap:a', 0), row('cap:full', 60_000_000, value=b'"FULL"'), row('cap:b', 120_000_000))
    for ordering in permutations(samples):
        assert continuous(ordering) == ()


def test_a_new_continuous_run_can_qualify_after_the_different_state():
    samples = (row('cap:a', 0), row('cap:full', 60_000_000, value=b'"FULL"'),
               row('cap:b', 120_000_000), row('cap:c', 240_000_000))
    for ordering in permutations(samples):
        assert continuous(ordering) == (('cap:b', 'cap:c'),)


def test_same_state_intermediate_sample_preserves_continuity():
    assert continuous((row('cap:a', 0), row('cap:b', 60_000_000), row('cap:c', 120_000_000))) == (('cap:a', 'cap:c'),)


@pytest.mark.parametrize('samples', [
    (), (row('cap:a', 0),), (row('cap:a', None), row('cap:b', None)),
    (row('cap:a', 0), row('cap:b', 120_000_000, clock='collector:b')),
    (row('cap:a', 0, 121_000_000), row('cap:b', 120_000_000, 122_000_000)),
    (row('cap:a', 0), row('cap:b', 120_000_000, value=b'"FULL"')),
    (row('cap:a', 0, clock='node:sw-a/epoch:one'), row('cap:b', 120_000_000, clock='node:sw-a/epoch:one')),
])
def test_missing_or_unordered_collector_duration_never_produces_a_pair(samples):
    assert continuous(samples) == ()


def test_untimed_disagreement_is_still_a_settlement_blocker_even_with_a_duration_pair():
    samples = (row('cap:a', 0), row('cap:b', 120_000_000), row('cap:unknown', None, value=b'"FULL"'))
    assert continuous(samples) == (('cap:a', 'cap:b'),)
    assert settled_captures(tuple((capture, observed) for capture, observed, _ in samples)) == ('cap:b', 'cap:unknown')


@pytest.mark.parametrize('separation_s', [-1, True, 1.0])
def test_invalid_separation_is_refused(separation_s):
    with pytest.raises(ValueError):
        continuous((row('cap:a', 0), row('cap:b', 120_000_000)), separation_s=separation_s)


def test_duplicate_capture_and_mutable_value_keys_are_refused():
    with pytest.raises(ValueError):
        continuous((row('cap:a', 0), row('cap:a', 120_000_000)))
    with pytest.raises(ValueError):
        continuous((row('cap:a', 0, value=[]), row('cap:b', 120_000_000)))

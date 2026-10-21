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

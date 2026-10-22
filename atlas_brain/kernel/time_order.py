"""Collector partial order from architecture 1.5; sorting never proves time."""
from .states import CaptureId, require
from .time import BoundSource, TimeInterval


def collector_before(first: TimeInterval | None, second: TimeInterval | None) -> bool:
    """Only finite collector intervals on the same clock can prove strict order."""
    if first is None or second is None:
        return False
    return (first.bound is BoundSource.COLLECTOR_RECORDED
            and second.bound is BoundSource.COLLECTOR_RECORDED
            and first.clock.startswith('collector:')
            and first.clock == second.clock
            and first.latest is not None and second.earliest is not None
            and first.latest < second.earliest)


def settled_captures(samples: tuple[tuple[CaptureId, TimeInterval | None], ...]) -> tuple[CaptureId, ...]:
    """Return every maximal capture, including all captures of unknown order.

    Values, evidence union and transient continuity still belong to settlement;
    this function proves only which captures cannot be superseded by time.
    """
    require(type(samples) is tuple and all(type(row) is tuple and len(row) == 2 for row in samples), 'invalid_sample_rows')
    require(all(type(capture) is str and bool(capture) for capture, _ in samples), 'missing_sample_capture')
    require(len({capture for capture, _ in samples}) == len(samples), 'duplicate_sample_capture')
    require(all(observed is None or type(observed) is TimeInterval for _, observed in samples), 'invalid_sample_interval')
    return tuple(sorted(capture for capture, observed in samples
                        if not any(collector_before(observed, other) for _, other in samples)))


def continuous_collector_pairs(
    samples: tuple[tuple[CaptureId, TimeInterval | None, bytes], ...],
    *, target: bytes, minimum_separation_s: int,
) -> tuple[tuple[CaptureId, CaptureId], ...]:
    """Prove duration pairs on one continuous run, using integer microseconds.

    Keys are opaque equality inputs; canonical value encoding belongs upstream.
    The caller must separately settle all samples, including untimed disagreement,
    and admit their evidence. A duration pair alone never certifies a verdict.
    """
    require(type(samples) is tuple and all(type(row) is tuple and len(row) == 3 for row in samples), 'invalid_continuity_rows')
    require(type(target) is bytes and all(type(key) is bytes for _, _, key in samples), 'invalid_state_key')
    require(type(minimum_separation_s) is int and minimum_separation_s >= 0, 'invalid_separation')
    settled_captures(tuple((capture, observed) for capture, observed, _ in samples))
    separation_us = minimum_separation_s * 1_000_000
    pairs: set[tuple[CaptureId, CaptureId]] = set()
    for first, first_time, first_key in samples:
        for second, second_time, second_key in samples:
            if first_key != target or second_key != target or not collector_before(first_time, second_time):
                continue
            if first_time is None or second_time is None or first_time.latest is None or second_time.earliest is None:
                continue
            if second_time.earliest - first_time.latest < separation_us:
                continue
            if any(key != target and collector_before(first_time, observed) and collector_before(observed, second_time)
                   for _, observed, key in samples):
                continue
            pairs.add((first, second))
    return tuple(sorted(pairs))

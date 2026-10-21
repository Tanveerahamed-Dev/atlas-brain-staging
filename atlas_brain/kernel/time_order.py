"""Collector partial order from architecture 1.5; sorting never proves time."""
from .states import CaptureId, require
from .time import BoundSource, TimeInterval


def collector_before(first: TimeInterval | None, second: TimeInterval | None) -> bool:
    """Only finite collector intervals on the same clock can prove strict order."""
    if first is None or second is None:
        return False
    return (first.bound is BoundSource.COLLECTOR_RECORDED
            and second.bound is BoundSource.COLLECTOR_RECORDED
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

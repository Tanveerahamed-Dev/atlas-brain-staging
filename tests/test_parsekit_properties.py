"""Byte ownership, span round-trips and honest partial results over random input."""
from enum import StrEnum

from hypothesis import given, strategies as st

from atlas_brain.evidence.parsekit.rules import Rule, TokenMap, run_rules
from atlas_brain.kernel.states import CaptureId
class Duplex(StrEnum):
    HALF = "half"
    FULL = "full"


def table():
    return (Rule("duplex", "start", r"duplex (?P<duplex>\S+)", "record", "start", "", ("duplex",)),)


@given(st.binary(max_size=512))
def test_every_byte_has_exactly_one_line_and_values_round_trip(raw):
    rules = (Rule("all", "start", r"(?P<raw>[\s\S]*)", "record", "start", "", ("raw",)),)
    result = run_rules(raw, CaptureId("cap-a"), rules, ())
    assert result.quality == "complete"
    offsets = [i for line in result.lines for i in range(line.span.start, line.span.end)]
    assert offsets == list(range(len(raw)))
    for record in result.records:
        for _, field in record.fields:
            assert raw[field.span.start:field.span.end] == field.raw.encode("utf-8", "surrogateescape")


@given(st.binary(max_size=128))
def test_random_unmatched_line_is_never_silently_dropped(payload):
    raw = b"!" + payload.replace(b"\n", b"!") + b"\n"
    result = run_rules(raw, CaptureId("cap-a"), table(), ())
    assert result.quality == "partial"
    assert result.lines[0].status == "unrecognised"


@given(st.sampled_from(tuple(Duplex)))
def test_closed_map_preserves_each_mapped_enum(member):
    maps = (("duplex", TokenMap.closed({v.value: v for v in Duplex})),)
    result = run_rules(f"duplex {member.value}\n".encode(), CaptureId("cap-a"), table(), maps)
    assert result.quality == "complete"
    assert result.records[0].fields[0][1].value is member

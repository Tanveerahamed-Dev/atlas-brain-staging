"""The two plan-row planted failures precede the rule engine."""
from enum import StrEnum

from atlas_brain.evidence.parsekit.rules import Rule, TokenMap, run_rules
from atlas_brain.kernel.states import CaptureId, Unknown, UnknownReason


class Duplex(StrEnum):
    HALF = "half"
    FULL = "full"


def table():
    return (Rule("duplex", "start", r"duplex (?P<duplex>\S+)", "record", "start", "", ("duplex",)),)


def test_planted_unrecognised_line_is_partial():
    result = run_rules(b"duplex full\nnew firmware line\n", CaptureId("cap-a"), table(), ())
    assert result.quality == "partial"
    assert [line.status for line in result.lines] == ["consumed", "unrecognised"]
    assert len(result.records) == 1


def test_planted_unmapped_token_is_unknown_with_raw_kept():
    maps = (("duplex", TokenMap.closed({"half": Duplex.HALF, "full": Duplex.FULL})),)
    result = run_rules(b"duplex a-half\n", CaptureId("cap-a"), table(), maps)
    field = result.records[0].fields[0][1]
    assert result.quality == "partial"
    assert field.raw == "a-half"
    assert isinstance(field.value, Unknown)
    assert field.value.reason is UnknownReason.PARSE_PARTIAL
    assert field.value.evidence[0].locator == field.span


def test_ordered_states_and_cited_ignore():
    rules = (
        Rule("open", "start", "BEGIN", "enter_state", "body", "", ()),
        Rule("blank", "body", "", "ignore", "body", "fixture:blank separator", ()),
        Rule("value", "body", r"(?P<value>\d+)", "record", "body", "", ("value",)),
        Rule("close", "body", "END", "leave_state", "start", "", ()),
    )
    result = run_rules(b"BEGIN\r\n\r\n42\nEND", CaptureId("cap-a"), rules, ())
    assert result.quality == "complete"
    assert [line.rule_id for line in result.lines] == ["open", "blank", "value", "close"]
    assert result.lines[1].status == "ignored"
    assert result.records[0].fields[0][1].raw == "42"


def test_first_rule_wins_and_lone_cr_is_not_a_line_break():
    rules = (Rule("first", "start", r"(?P<value>[\s\S]*)", "record", "start", "", ("value",)),
             Rule("second", "start", r".*", "record", "start", "", ()))
    result = run_rules(b"a\rb\r\n", CaptureId("cap-a"), rules, ())
    assert len(result.lines) == 1
    assert result.records[0].rule_id == "first"
    assert result.records[0].fields[0][1].raw == "a\rb"


def test_invalid_ignore_and_undeclared_capture_are_refused():
    import pytest

    for rule in (Rule("bad", "start", "", "ignore", "start", "", ()),
                 Rule("bad", "start", r"(?P<x>.*)", "record", "start", "", ())):
        with pytest.raises(ValueError):
            run_rules(b"\n", CaptureId("cap-a"), (rule,), ())


def test_empty_capture_does_not_invent_a_record():
    result = run_rules(b"", CaptureId("cap-a"), table(), ())
    assert result.lines == result.records == ()

"""Planted regex violations are rejected before a pattern can run."""
import re

import pytest

from atlas_brain.evidence.parsekit.patterns import compile_pattern


@pytest.mark.parametrize("pattern", [
    r"(a+)+", r"(?:a*){2,}", r"((ab){1,3})?", r"(a|aa)+",
    r"(?P<word>a+)\\s+(?P=word)", r"(a)\1", r"(?=a)a", r"(?i:a)",
])
def test_planted_backtracking_shapes_refused(pattern):
    with pytest.raises(ValueError):
        compile_pattern(pattern)


@pytest.mark.parametrize("pattern,text", [
    (r"(?P<name>[A-Za-z]+) (?P<value>\d+)", b"port 12"),
    (r"(?:up|down)", b"up"), (r"[()+*?{}]+", b"(*)"),
    (r"a+?", b"aaa"), (r"a++", b"aaa"), (r"\(a\+\)", b"(a+)"),
    (r"[]a]+", b"]a"),
])
def test_safe_patterns_run(pattern, text):
    compiled = compile_pattern(pattern)
    assert compiled.flags & re.ASCII
    assert compiled.fullmatch(text)


def test_invalid_regex_is_refused():
    with pytest.raises(ValueError):
        compile_pattern("[")


def test_ascii_digit_class_does_not_accept_unicode():
    assert compile_pattern(r"\d+").fullmatch("١".encode()) is None


@pytest.mark.parametrize("pattern", [r"(a{,3})+", r"(a{,})+", r"(a{2}){,4}"])
def test_omitted_repeat_lower_bound_cannot_bypass_lint(pattern):
    with pytest.raises(ValueError):
        compile_pattern(pattern)

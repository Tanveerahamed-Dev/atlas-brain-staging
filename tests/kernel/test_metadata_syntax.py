"""Syntax markers return booleans, never live SDK types or interpreter handles."""
import ast

import pytest


@pytest.mark.parametrize('source,expected', [
    ('value += other', True),
    ('owned[0] |= other', True),
    ('value = other', False),
    ('owned[0] = other', False),
    ('for value in other:\n pass', False),
    ('(value := other)', False),
    ('value + other', False),
])
def test_in_place_write_marker(source, expected):
    from atlas_brain.kernel.token_lints import inplace_write

    assert inplace_write(ast.parse(source).body[0]) is expected

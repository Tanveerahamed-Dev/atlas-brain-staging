"""Total successor syntax metadata refuses missing domain entries."""
import ast
import inspect

import pytest

from atlas_brain.kernel import lints, token_lints


def test_successor_subscription_distinguishes_empty_from_missing():
    lookup = getattr(token_lints, 'successor_value', None)
    assert lookup is not None
    tree = ast.parse('first()\nsecond()')
    first, second = tree.body
    assert lookup(first, {first: (second,)}) == (second,)
    assert lookup(second, {second: ()}) == ()
    with pytest.raises(KeyError):
        lookup(ast.Name(id='other'), {second: ()})



def test_successor_consumer_source_has_no_missing_key_default():
    source = inspect.getsource(token_lints.fallback_nodes)
    assert not tuple(item for item in lints.lint(source, 'atlas_brain/kernel/probe.py') if item[0] == 3)

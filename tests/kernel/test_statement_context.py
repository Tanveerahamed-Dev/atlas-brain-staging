import ast

import pytest

from atlas_brain.kernel.token_lints import statement_context


@pytest.mark.parametrize('source,protected', [
    ('def mapped(raw):\n if raw == "up": return "up"\n raise ValueError("unmapped")', False),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except ValueError: return "up"', True),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n finally: return "up"', True),
    ('def mapped(raw):\n with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', True),
    ('async def mapped(raw):\n async with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', True),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except* ValueError: pass', True),
    ('def mapped(raw):\n try: pass\n except ValueError: pass\n else:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', False),
    ('def mapped(raw):\n try: pass\n except ValueError:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', False),
    ('def mapped(raw):\n try:\n  try:\n   if raw == "up": return "up"\n   raise ValueError("unmapped")\n  finally: pass\n except ValueError: return "up"', True),
    ('with manager:\n def mapped(raw):\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', False),
])
def test_exception_and_finalization_context_is_retained_across_statement_blocks(source, protected):
    tree = ast.parse(source)
    following, intercepted = statement_context(tree)
    branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If))
    assert isinstance(following[branch][-1], ast.Raise)
    assert (branch in intercepted) is protected


def test_successor_inventory_is_bound_to_each_exact_statement_list():
    tree = ast.parse('if ready:\n first()\n second()\nelse:\n other()\nafter()')
    following, intercepted = statement_context(tree)
    branch = tree.body[0]
    assert isinstance(branch, ast.If)
    assert following[branch] == (tree.body[1],)
    assert following[branch.body[0]] == (branch.body[1],)
    assert following[branch.orelse[0]] == ()
    assert not intercepted

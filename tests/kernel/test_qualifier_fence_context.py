"""Runtime data witnesses paired with the unchanged C1 source fence."""
import ast
import inspect
from textwrap import dedent

import pytest

from tools.fence import source_refusals


def qualifier_tree_dictionary(source):
    trees = {'source': ast.parse(source)}
    result = []
    for label, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                result.append((label, node.id))
    return tuple(result)


def qualifier_tree_comprehension(source):
    sources = {'source': source}
    trees = {label: ast.parse(text) for label, text in sources.items()}
    result = []
    for label, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                result.append((label, node.id))
    return tuple(result)


def qualifier_function_dictionary(source):
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    result = []
    for name, function in functions.items():
        result.append((name.rsplit('.', 1)[-1], len(function.body)))
    return tuple(result)


@pytest.mark.parametrize('fixture,program,expected', [
    (qualifier_tree_dictionary, 'symbol', (('source', 'symbol'),)),
    (qualifier_tree_comprehension, 'symbol', (('source', 'symbol'),)),
    (qualifier_function_dictionary, 'def sampled():\n pass\n', (('sampled', 1),)),
])
def test_real_ast_dictionary_data_remains_ordinary_metadata(fixture, program, expected):
    # Execute an ordinary fixture, never exec/eval the source being checked.
    assert fixture(program) == expected
    source = 'import ast\n' + dedent(inspect.getsource(fixture))
    path = 'atlas_brain/kernel/lints.py'
    refused = source_refusals(source, {path: source}, path)
    assert not refused, repr(sorted(refused))


@pytest.mark.parametrize('fixture', [qualifier_tree_dictionary, qualifier_tree_comprehension, qualifier_function_dictionary])
def test_same_ast_dictionary_does_not_admit_an_unlisted_api(fixture):
    source = 'import ast\n' + dedent(inspect.getsource(fixture))
    source += '\nvalue = ast.literal_eval("1")\n'
    path = 'atlas_brain/kernel/lints.py'
    refused = source_refusals(source, {path: source}, path)
    assert 'ast.literal_eval' in refused

"""Actual e50 carrier reduction, not an isolated dictionary admission claim."""
import ast
import hashlib
import inspect
import json
from pathlib import Path
from textwrap import dedent

import pytest

from tools.fence import ImportIndex, import_bindings, source_refusals

SOURCE_HEAD = 'e50bf6ad9ed61914025da80534c27db727831bfb'
PRODUCER = 'atlas_brain/kernel/lints.py'
CONSUMER = 'atlas_brain/kernel/carrier_consumer.py'
MARKER = '$carrier:ast.parse.items.id'
DELETION_ONLY = """import ast

def qualifier_witnesses(source: str, path: str, sources: dict[str, str], inventory: tuple[str, ...]) -> tuple[int, ...]:
    try:
        trees = {p: ast.parse(text) for p, text in sources.items()}
    except SyntaxError:
        pass
    metadata = {p for p, tree in trees.items() if any((isinstance(n, ast.Import) and any((a.name == 'ast' and a.asname is None for a in n.names)) for n in tree.body))}
    for p in metadata:
        module, tree = (modules[p], trees[p])
        for reference_node in ast.walk(tree):
            if target not in functions:
                if isinstance(parent, ast.Call) and parent.func is reference_node and (reference_node.id not in builtins) and (reference_node.id not in local):
                    pass
"""


def carrier_probe(sources: dict[str, str]) -> bool:
    trees = {p: ast.parse(text) for p, text in sources.items()}
    modules = {p: p[:-3] for p in sources}
    metadata = {p for p, tree in trees.items() if tree}
    for p in metadata:
        module, tree = modules[p], trees[p]
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for reference_node in ast.walk(tree):
            if not isinstance(reference_node, ast.Name):
                continue
            parent = parents[reference_node]
            if isinstance(parent, ast.Call) and parent.func is reference_node and reference_node.id not in ():
                return bool(module) and reference_node.id == 'check'
    return False


def carrier_safe(sources: dict[str, str]) -> bool:
    trees = dict((p, ast.parse(text)) for p, text in sources.items())
    modules = {p: p[:-3] for p in sources}
    metadata = {p for p, tree in trees.items() if tree}
    for p in metadata:
        module, tree = modules[p], trees[p]
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for reference_node in ast.walk(tree):
            if not isinstance(reference_node, ast.Name):
                continue
            parent = parents[reference_node]
            if isinstance(parent, ast.Call) and parent.func is reference_node and reference_node.id not in ():
                return bool(module) and reference_node.id == 'check'
    return False


def carrier_capability(sources: dict[str, str]):
    trees = dict((p, ast.parse) for p, text in sources.items())
    modules = {p: p[:-3] for p in sources}
    metadata = {p for p, tree in trees.items() if tree}
    for p in metadata:
        module, tree = modules[p], trees[p]
        if module:
            return tree
    return None


def invoke_capability(sources):
    operation = carrier_capability(sources)
    return operation('symbol')


def fixture_source(function):
    text = dedent(inspect.getsource(function))
    return 'import ast\n' + text.replace('def ' + function.__name__ + '(', 'def carrier_probe(')


def context(source):
    sources = {p.as_posix(): p.read_text(encoding='utf-8')
               for p in sorted(Path('atlas_brain').rglob('*.py'))}
    sources[PRODUCER] = source
    return sources


def observed_bindings(source):
    tree = ast.parse(source)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    _, full, declarations = import_bindings(tree, PRODUCER)
    function.body = function.body[:1]
    _, prefix, prefix_declarations = import_bindings(tree, PRODUCER)
    keys = ('carrier_probe.trees', 'carrier_probe.metadata', 'carrier_probe.tree',
            'carrier_probe.reference_node', 'carrier_probe.$return')
    return {
        'first_assignment': {'export': prefix['carrier_probe.trees']} if 'carrier_probe.trees' in prefix else {
            'declared': 'carrier_probe.trees' in prefix_declarations},
        'full': {key: {'export': full[key]} if key in full else {'declared': key in declarations}
                 for key in keys},
    }


def emit(capsys, receipt):
    with capsys.disabled():
        print('K_CARRIER_PAIR ' + json.dumps(receipt, sort_keys=True))


@pytest.mark.parametrize('callee,expected', [('check', True), ('other', False)])
def test_closed_ordinary_data_and_safe_control_return_only_boolean(callee, expected):
    sources = {'case.py': 'import ast\n' + callee + '(symbol)\n'}
    for function in (carrier_probe, carrier_safe):
        result = function(sources)
        assert type(result) is bool and result is expected


def test_actual_reduction_and_control_preserve_current_fence_verdict(capsys):
    assert hashlib.sha256(DELETION_ONLY.encode()).hexdigest() == (
        '03143606e3e2899466784b31c492e260835c9afceaa15fc50dea45f0635e7529')
    assert source_refusals(DELETION_ONLY, context(DELETION_ONLY), PRODUCER) == {MARKER}
    blocked, safe = fixture_source(carrier_probe), fixture_source(carrier_safe)
    assert safe == blocked.replace('{p: ast.parse(text) for p, text in sources.items()}',
                                   'dict((p, ast.parse(text)) for p, text in sources.items())')
    blocked_hits = source_refusals(blocked, context(blocked), PRODUCER)
    safe_hits = source_refusals(safe, context(safe), PRODUCER)
    blocked_bindings, safe_bindings = observed_bindings(blocked), observed_bindings(safe)
    receiver_lines = sorted({n.lineno for n in ast.walk(ast.parse(blocked))
                             if isinstance(n, ast.Attribute) and n.attr == 'id'})
    emit(capsys, {'origin_head': SOURCE_HEAD, 'path': PRODUCER,
                  'fence_sha256': hashlib.sha256(Path('tools/fence.py').read_bytes()).hexdigest(),
                  'blocked_source_sha256': hashlib.sha256(blocked.encode()).hexdigest(),
                  'safe_source_sha256': hashlib.sha256(safe.encode()).hexdigest(),
                  'receiver_lines': receiver_lines, 'blocked': sorted(blocked_hits), 'safe': sorted(safe_hits),
                  'blocked_bindings': blocked_bindings, 'safe_bindings': safe_bindings})
    assert MARKER in blocked_hits
    assert not safe_hits
    assert blocked_bindings['first_assignment'] != safe_bindings['first_assignment']


def test_actual_callable_traverses_same_collector_and_is_refused_at_unadmitted_invocation(capsys):
    inputs = {'case.py': 'import ast\ncheck(symbol)\n'}
    operation = carrier_capability(inputs)
    assert operation is ast.parse
    parsed = invoke_capability(inputs)
    assert isinstance(parsed, ast.Module) and isinstance(parsed.body[0], ast.Expr)
    assert isinstance(parsed.body[0].value, ast.Name) and parsed.body[0].value.id == 'symbol'
    producer = fixture_source(carrier_capability)
    caller = ('from atlas_brain.kernel.lints import carrier_probe\n' +
              dedent(inspect.getsource(invoke_capability)).replace('carrier_capability(', 'carrier_probe('))
    sources = context(producer)
    sources[CONSUMER] = caller
    producer_hits = source_refusals(producer, sources, PRODUCER)
    caller_hits = source_refusals(caller, sources, CONSUMER)
    roots = ImportIndex(sources).foreign_roots('$result:atlas_brain.kernel.lints.carrier_probe', callable_value=True)
    emit(capsys, {'capability_source_sha256': hashlib.sha256(producer.encode()).hexdigest(),
                  'consumer_path': CONSUMER, 'producer': sorted(producer_hits),
                  'caller': sorted(caller_hits), 'observed_result_roots': sorted(roots)})
    assert not producer_hits
    assert '$result:atlas_brain.kernel.lints.carrier_probe()' in caller_hits
    assert any(root.removeprefix('$carrier:') == 'ast.parse' for root in roots)


def test_genuine_unlisted_api_remains_refused():
    source = fixture_source(carrier_safe) + '\nvalue = ast.literal_eval("1")\n'
    assert source_refusals(source, context(source), PRODUCER) == {'ast.literal_eval'}

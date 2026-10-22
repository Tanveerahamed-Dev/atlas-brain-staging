"""Closed read-only helper grammar; unproved values never acquire write authority."""
import ast
from pathlib import Path

import pytest


def definitions(tree, module):
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    functions = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        names = []
        parent = node
        while parent in parents:
            if isinstance(parent, ast.FunctionDef):
                names.append(parent.name)
            parent = parents[parent]
        functions[module + '.' + '.'.join(reversed(names))] = node
    return functions


def check(body):
    from atlas_brain.kernel.metadata_readonly import readonly_functions

    source = ('import ast\ndef lint(source, path):\n    findings = set()\n'
              + body + '\n    return tuple(sorted(findings))\n')
    functions = definitions(ast.parse(source), 'case')
    imports = {key: {'ast': 'ast'} for key in functions}
    return readonly_functions(functions, imports, 'case.lint')


@pytest.mark.parametrize('body', [
    '    findings.add((3, 1))',
    '    parts = source.splitlines()',
    '    joined = ".".join(source.split("."))',
    '    owned = []\n    owned.append(source)\n    owned.pop()',
    '    owned = {}\n    owned["metadata"] = source',
    '    owned = [False]\n    owned[-1] = True',
    '    owned = [False]\n    owned[-1] = owned[-1] or True',
    '    owned = set()\n    owned.add(source)',
    '    def hit():\n        findings.add((3, 1))\n    hit()',
    '    def read(data=frozenset()):\n        return len(data)\n    size = read()',
    ('    def echo(data):\n        return data\n'
     '    forwarded = echo(source)\n    size = len(forwarded)'),
    '    for node in ast.walk(ast.parse(source)):\n        findings.add((3, node.lineno))',
])
def test_owned_collections_and_transitive_readers_remain_supported(body):
    assert check(body)


@pytest.mark.parametrize('body', [
    '    forwarded = source\n    forwarded["forged"] = "healthy"',
    '    forwarded = source.body\n    forwarded[:] = ()',
    '    forwarded = source\n    forwarded |= {"forged": "healthy"}',
    '    owned = [source]\n    owned[0] |= {"forged": "healthy"}',
    '    owned = [source]\n    owned[0] += ["healthy"]',
    '    source.append("healthy")',
    '    def consume(data=source.clear()):\n        return len(data)\n    size = consume()',
    '    owned = {}\n    owned = source\n    owned["forged"] = "healthy"',
    ('    def consume(data):\n        forwarded = data\n'
     '        forwarded["forged"] = "healthy"\n    consume(source)'),
    '    source.unknown_operation()',
    '    external(source)',
    '    return source',
    '    yield source',
    '    global cached\n    cached = source',
    ('    cached = source\n    def consume():\n        nonlocal cached\n'
     '        cached = {}\n    consume()'),
    '    list = source\n    owned = list()\n    owned.append(1)',
    '    ast.increment_lineno(source)',
    '    callback = ast.increment_lineno\n    callback(source)',
    '    ordered = sorted(tuple(source), key=source.pop)',
    '    callback = source.clear\n    callback()',
    '    ordered = sorted(("forged",), key=source.setdefault)',
    '    ordered = sorted(tuple(source), key=source.__delitem__)',
    '    owned = {}\n    box = [source]\n    box[0]["forged"] = "healthy"',
    ('    def consume(findings):\n        findings.add((3, 1))\n'
     '    consume(source)'),
])
def test_unproved_mutation_escape_and_calls_fail_closed(body):
    assert not check(body)


def test_actual_metadata_context_has_no_readonly_refusal():
    from atlas_brain.kernel.metadata_readonly import readonly_failure

    functions, imports = {}, {}
    for path in sorted(Path('atlas_brain').rglob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        if not any(isinstance(n, ast.Import) and any(a.name == 'ast' and a.asname is None for a in n.names) for n in tree.body):
            continue
        module = path.as_posix()[:-3].replace('/', '.').removesuffix('.__init__')
        local = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
            if isinstance(node, ast.ImportFrom):
                package = module.split('.')[:-1]
                prefix = '.'.join(package[:len(package) - node.level + 1] + ([node.module] if node.module else [])) if node.level else node.module
                for alias in node.names:
                    local[alias.asname or alias.name] = prefix + '.' + alias.name
        found = definitions(tree, module)
        functions.update(found)
        imports.update((key, local) for key in found)
    reason = readonly_failure(functions, imports, 'atlas_brain.kernel.lints.lint')
    assert reason == '', reason

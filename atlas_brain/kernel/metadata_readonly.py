"""Finite ownership grammar for a closed graph of metadata readers.

Parameters, call results and aliases are read-only by default. Only a uniquely
bound local built-in collection can receive writes; its contents stay read-only.
The caller separately proves graph closure, source coverage and finding outputs.
"""
import ast

BUILTINS = ('isinstance', 'dict', 'tuple', 'any', 'all', 'sorted', 'str', 'type',
            'set', 'list', 'len', 'next', 'iter', 'enumerate', 'bool', 'frozenset',
            'int', 'reversed', 'zip')
READ_METHODS = ('items', 'keys', 'values', 'split', 'rsplit', 'splitlines', 'join', 'startswith',
                'endswith', 'replace', 'removesuffix', 'encode', 'hexdigest')
MUTATORS = ('append', 'extend', 'add', 'update', 'pop', 'clear', 'remove', 'setdefault',
            'insert', 'discard', 'sort', 'reverse', 'difference_update',
            'intersection_update', 'symmetric_difference_update', 'popitem')
PURE_CALLS = ('ast.parse', 'ast.walk', 'ast.iter_child_nodes', 'ast.iter_fields',
              'ast.Name', 'ast.Load', 're.search', 'hashlib.sha256', 'typing.cast')


def local_nodes(function: ast.FunctionDef) -> tuple[ast.AST, ...]:
    """Each nested function is checked in its own lexical scope."""
    pending: list[ast.AST] = list(function.body)
    nodes: list[ast.AST] = []
    while pending:
        node = pending.pop()
        nodes.append(node)
        if isinstance(node, ast.FunctionDef):
            pending.extend(node.args.defaults)
            pending.extend(default for default in node.args.kw_defaults if default is not None)
            pending.extend(node.decorator_list)
        else:
            pending.extend(ast.iter_child_nodes(node))
    return tuple(nodes)


def fresh_collection(value: ast.AST) -> bool:
    return isinstance(value, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)) or (
        isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
        and value.func.id in ('list', 'dict', 'set'))


def public_result(node: ast.Return) -> bool:
    value = node.value
    if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
            and value.func.id == 'tuple' and len(value.args) == 1 and not value.keywords):
        return False
    ordered = value.args[0]
    return (isinstance(ordered, ast.Call) and isinstance(ordered.func, ast.Name)
            and ordered.func.id == 'sorted' and len(ordered.args) == 1 and not ordered.keywords
            and isinstance(ordered.args[0], ast.Name) and ordered.args[0].id == 'findings')


def readonly_failure(functions: dict[str, ast.FunctionDef],
                       imports: dict[str, dict[str, str]], public_root: str) -> str:
    """Return a scalar refusal reason, or an empty string for this finite grammar."""
    detail = ""
    if public_root not in functions or set(imports) != set(functions):
        return f"R1:{detail}"
    bindings: dict[tuple[str, str], tuple[ast.AST, ...]] = {}
    candidates: dict[tuple[str, str], ast.Name] = {}
    scopes: dict[str, tuple[ast.AST, ...]] = {}
    type_nodes: set[ast.AST] = set()

    def bind(scope: str, name: str, node: ast.AST) -> None:
        key = scope, name
        if key not in bindings:
            bindings[key] = (node,)
            return
        bindings[key] = (*bindings[key], node)

    for key, function in functions.items():
        detail = key
        if function.type_params or function.decorator_list:
            return f"R3:{detail}"
        nodes = local_nodes(function)
        scopes[key] = nodes
        args = function.args.posonlyargs + function.args.args + function.args.kwonlyargs
        if function.args.vararg is not None:
            args = [*args, function.args.vararg]
        if function.args.kwarg is not None:
            args = [*args, function.args.kwarg]
        for argument in args:
            bind(key, argument.arg, argument)
            if argument.annotation is not None:
                type_nodes.update(ast.walk(argument.annotation))
        if function.returns is not None:
            type_nodes.update(ast.walk(function.returns))
        for node in nodes:
            if isinstance(node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom,
                                 ast.With, ast.AsyncWith, ast.Match, ast.ClassDef,
                                 ast.Lambda, ast.AsyncFunctionDef, ast.Import, ast.ImportFrom)):
                return f"R4:{detail}"
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                bind(key, node.id, node)
            if isinstance(node, ast.FunctionDef):
                bind(key, node.name, node)
            if isinstance(node, ast.ExceptHandler) and node.name:
                bind(key, node.name, node)
            if isinstance(node, ast.AnnAssign):
                type_nodes.update(ast.walk(node.annotation))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(targets) == 1 and isinstance(targets[0], ast.Name) and node.value is not None and fresh_collection(node.value):
                    candidates[key, targets[0].id] = targets[0]
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and len(node.args) > 1 and (
                    node.func.id == 'isinstance' or node.func.id in imports[key] and imports[key][node.func.id] == 'typing.cast'):
                type_nodes.update(ast.walk(node.args[1 if node.func.id == 'isinstance' else 0]))
    if any(name in BUILTINS or name in imports[key] for key, name in bindings):
        return f"R2:{detail}"
    owned = {key for key, target in candidates.items() if bindings[key] == (target,)}

    def lexical(scope: str, name: str) -> str:
        while scope in functions:
            if (scope, name) in bindings:
                return scope
            scope = scope.rsplit('.', 1)[0]
        return ''

    def known_function(scope: str, name: str) -> bool:
        owner = lexical(scope, name)
        if owner:
            entries = bindings[owner, name]
            return len(entries) == 1 and isinstance(entries[0], ast.FunctionDef) and owner + '.' + name in functions
        while scope in functions:
            scope = scope.rsplit('.', 1)[0]
        return scope + '.' + name in functions

    for key, nodes in scopes.items():
        detail = key
        parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        local = imports[key]
        for node in nodes:
            if isinstance(node, ast.Attribute) and (node.attr.startswith('__') or node.attr in MUTATORS):
                if node.attr.startswith('__') or node not in parents:
                    return f"R7:{detail}"
                parent = parents[node]
                if not (isinstance(parent, ast.Call) and parent.func is node):
                    return f"R8:{detail}"
            if isinstance(node, ast.Return) and key == public_root and not public_result(node):
                return f"R5:{detail}"
            if (isinstance(node, (ast.Attribute, ast.Subscript)) and not isinstance(node.ctx, ast.Load)
                    and not (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                        and (lexical(key, node.value.id), node.value.id) in owned)):
                return f"R6:{detail}"
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in local:
                target = local[node.value.id] + '.' + node.attr
                if node not in type_nodes and target != 're.ASCII':
                    if node not in parents:
                        return f"R10:{detail}"
                    parent = parents[node]
                    if not (isinstance(parent, ast.Call) and parent.func is node and target in PURE_CALLS):
                        return f"R11:{detail}"
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in local:
                    if local[name] not in PURE_CALLS and local[name] not in functions:
                        return f"R12:{detail}"
                elif name not in BUILTINS and not known_function(key, name):
                    return f"R13:{detail}"
            elif isinstance(node.func, ast.Attribute):
                receiver, method = node.func.value, node.func.attr
                if isinstance(receiver, ast.Name) and receiver.id in local:
                    if local[receiver.id] + '.' + method not in PURE_CALLS:
                        return f"R14:{detail}"
                elif method in MUTATORS:
                    if not (isinstance(receiver, ast.Name) and (lexical(key, receiver.id), receiver.id) in owned):
                        return f"R15:{detail}"
                elif method not in READ_METHODS:
                    return f"R16:{detail}"
            else:
                return f"R9:{detail}"
    return ''


def readonly_functions(functions: dict[str, ast.FunctionDef],
                       imports: dict[str, dict[str, str]], public_root: str) -> bool:
    """Keep the public boolean contract separate from scalar diagnostics."""
    return not readonly_failure(functions, imports, public_root)

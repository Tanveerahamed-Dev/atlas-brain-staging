"""Import-origin witnesses for conservative lint guards."""
import ast
import re

from .token_lints import bound_names


def nested_unbounded(pattern: str) -> bool:
    """Track groups, escaped characters and character classes before repeats."""
    stack: list[bool] = [False]
    last_group = False
    escaped = in_class = False
    for index, char in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            last_group = False
            continue
        if char == '[':
            in_class = True
            last_group = False
        if in_class:
            if char == ']':
                in_class = False
            continue
        if char == '(':
            stack.append(False)
        elif char == ')':
            last_group = stack.pop() if len(stack) > 1 else False
            stack[-1] |= last_group
            continue
        elif char in '*+' or (char == '{' and re.search(r'^\{\d+,\}', pattern[index:], re.ASCII)):
            if last_group:
                return True
            stack[-1] = True
        last_group = False
    return False


def resolved_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve an AST name using the scanner's supplied import environment."""
    if isinstance(node, ast.Name):
        if node.id not in aliases:
            return node.id
        return aliases[node.id]
    if isinstance(node, ast.Attribute):
        return resolved_name(node.value, aliases) + '.' + node.attr
    if isinstance(node, ast.Subscript):
        return resolved_name(node.value, aliases)
    return ''


def resolved_tail(node: ast.AST, aliases: dict[str, str]) -> str:
    return resolved_name(node, aliases).split('.')[-1]


def contains_name(node: ast.AST, names: tuple[str, ...], aliases: dict[str, str]) -> bool:
    return any(resolved_tail(part, aliases) in names for part in ast.walk(node))


def import_bindings(tree: ast.AST) -> tuple[tuple[str, str], ...]:
    """Retain every import origin; a nested alias cannot erase an outer target."""
    bindings: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                bindings.append((item.asname or item.name.split('.')[0], item.name if item.asname else item.name.split('.')[0]))
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                bindings.append((item.asname or item.name, f'{node.module}.{item.name}'))
    return tuple(bindings)


def import_origins(tree: ast.AST) -> dict[str, tuple[str, ...]]:
    bindings = import_bindings(tree) + implicit_builtin_bindings(tree)
    return {name: tuple(sorted({origin for key, origin in bindings if key == name})) for name, _ in bindings}


def implicit_builtin_bindings(tree: ast.AST) -> tuple[tuple[str, str], ...]:
    """Retain builtin may-origins without treating a child scope's import as global."""
    targets = ('BaseException', 'float', 'frozenset', 'open', 'set', '__import__')
    rebound = set(bound_names(tree))
    rebound.update(node.id for node in ast.walk(tree)
                   if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load))
    rebound.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    rebound.update(node.name for node in ast.walk(tree)
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    rebound.update(node.name for node in ast.walk(tree)
                   if isinstance(node, ast.ExceptHandler) and node.name is not None)

    def visit(node: ast.AST, scopes: tuple[
            ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, ...
    ]) -> tuple[tuple[str, str], ...]:
        found: list[tuple[str, str]] = []
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in targets:
            prior_import = any(
                name == node.id and (statement.lineno, statement.col_offset) < (node.lineno, node.col_offset)
                for scope in scopes for statement in scope.body
                if isinstance(statement, (ast.Import, ast.ImportFrom))
                for name, _ in import_bindings(statement))
            if node.id in rebound or not prior_import:
                found.append((node.id, 'builtins.' + node.id))
        children = tuple(ast.iter_child_nodes(node))
        comprehensions = tuple(child for child in children if isinstance(child, ast.comprehension))
        if comprehensions:
            first = comprehensions[0]
            inner_scopes = tuple(scope for scope in scopes if not isinstance(scope, ast.ClassDef))
            for child in children:
                if child is first:
                    for part in ast.iter_child_nodes(child):
                        found.extend(visit(part, scopes if part is first.iter else inner_scopes))
                else:
                    found.extend(visit(child, inner_scopes))
            return tuple(found)
        body: tuple[ast.AST, ...] = ()
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = tuple(node.body)
        elif isinstance(node, ast.Lambda):
            body = (node.body,)
        for child in children:
            visible = scopes
            if child in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    visible = tuple(scope for scope in scopes if not isinstance(scope, ast.ClassDef))
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visible += (node,)
            found.extend(visit(child, visible))
        return tuple(found)

    return visit(tree, ())


def possible_names(node: ast.AST, origins: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        if node.id not in origins:
            return (node.id,)
        return origins[node.id]
    if isinstance(node, ast.Attribute):
        return tuple(name + '.' + node.attr for name in possible_names(node.value, origins))
    if isinstance(node, ast.Subscript):
        return possible_names(node.value, origins)
    return ('',)


def may_contain_name(node: ast.AST, names: tuple[str, ...], origins: dict[str, tuple[str, ...]]) -> bool:
    return any(name.split('.')[-1] in names for part in ast.walk(node) for name in possible_names(part, origins))


def binding_environment(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Collect imports; conflicting origins cannot certify a stable API binding."""
    bindings = import_bindings(tree)
    aliases = dict(bindings)
    ambiguous = {origin for name, origin in bindings if any(
        name == other and origin != candidate for other, candidate in bindings)}
    rebound = {resolved_name(n, aliases) for n in ast.walk(tree) if isinstance(n, (ast.Name, ast.Attribute)) and isinstance(n.ctx, ast.Store)}
    for binding in ast.walk(tree):
        identifier = binding.arg if isinstance(binding, ast.arg) else binding.name if isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)) else ''
        if identifier:
            rebound.add(resolved_name(ast.Name(id=identifier, ctx=ast.Load()), aliases))
    return aliases, rebound | ambiguous


def unordered_iterations(tree: ast.AST, aliases: dict[str, str]) -> frozenset[ast.AST]:
    """Refuse unordered iteration through every possible imported collection origin."""
    origins = {name: (origin,) for name, origin in aliases.items()} | import_origins(tree)
    sets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and may_contain_name(node.annotation, ('set', 'frozenset'), origins) and isinstance(node.target, ast.Name):
            sets.add(node.target.id)
        if isinstance(node, ast.arg) and node.annotation and may_contain_name(node.annotation, ('set', 'frozenset'), origins):
            sets.add(node.arg)
        if isinstance(node, (ast.Assign, ast.NamedExpr)):
            value = node.value
            if isinstance(value, (ast.Set, ast.SetComp)) or (isinstance(value, ast.Call) and any(name.split('.')[-1] in ('set', 'frozenset') for name in possible_names(value.func, origins))):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                sets.update(t.id for t in targets if isinstance(t, ast.Name))
    findings: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            iterator = node.iter
            if isinstance(iterator, (ast.Set, ast.SetComp)) or (isinstance(iterator, ast.Name) and iterator.id in sets) or (isinstance(iterator, ast.Call) and any(name.split('.')[-1] in ('set', 'frozenset') for name in possible_names(iterator.func, origins))):
                findings.add(node)
    return frozenset(findings)

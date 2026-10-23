"""Import origin certainty and node guards for the public lint scanner."""
import ast
import re

from .token_lints import bound_names

STATES = ('Known', 'Absent', 'Unknown', 'NotApplicable')
RUNNER = ('atlas_brain/runner/__main__.py', 'atlas_brain/runner/worker.py',
          'atlas_brain/runner/coordinator.py')
LOADER = 'atlas_brain/model/catalogue.py'
FACT_PATH = ('kernel', 'model', 'packs', 'correlate', 'timeline')
DENIED = ('ctypes', 'cffi', 'socket', 'ssl', 'subprocess', 'multiprocessing',
          'http', 'urllib.request', 'requests', 'httpx', 'aiohttp')


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


def node_rules(node: ast.AST, path: str, aliases: dict[str, str], origins: dict[str, tuple[str, ...]],
               rebound: set[str], shadowed: set[str], *, fact_path: bool, fact_fields: bool,
               in_verdict: bool, in_pk_compiler: bool, pk_compiler_source: bool) -> tuple[tuple[int, int], ...]:
    """Apply node-local guards; the source scanner supplies checked scope witnesses."""
    def ascii_flag(node: ast.AST) -> bool:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return ascii_flag(node.left) or ascii_flag(node.right)
        return resolved_name(node, aliases) in ('re.ASCII', 're.A') and resolved_name(node, aliases) not in rebound and 're' not in rebound

    def classvar(annotation: ast.AST) -> bool:
        root = annotation.value if isinstance(annotation, ast.Subscript) else annotation
        names = possible_names(root, origins)
        return contains_name(root, ('ClassVar',), aliases) and len(names) == 1 and all(
            name == 'typing.ClassVar' and not any(name == key or name.startswith(key + '.') or key.startswith(name + '.')
                for key in sorted(shadowed)) for name in names)

    findings: set[tuple[int, int]] = set()

    def hit(rule: int, node: ast.AST) -> None:
        findings.add((rule, node.lineno if isinstance(node, (ast.stmt, ast.expr, ast.ExceptHandler)) else 1))

    if isinstance(node, ast.AnnAssign) and fact_fields and (may_contain_name(node.annotation, ('Optional',), origins) or
            any(isinstance(n, ast.Constant) and n.value is None for n in ast.walk(node.annotation))):
        hit(1, node)
    if isinstance(node, ast.ClassDef):
        if any(name.split('.')[-1] in STATES for b in node.bases for name in possible_names(b, origins)):
            hit(13, node)
        record = any(name.split('.')[-1] == 'dataclass' for d in node.decorator_list for name in possible_names(d.func if isinstance(d, ast.Call) else d, origins))
        if record:
            for field in node.body:
                if isinstance(field, ast.AnnAssign) and field.value is not None and not classvar(field.annotation):
                    hit(2, field)
    if isinstance(node, ast.ExceptHandler) and (node.type is None or may_contain_name(node.type, ('BaseException',), origins)):
        hit(5, node)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or '', *[f'{node.module}.{a.name}' for a in node.names]]
        for module in modules:
            if fact_path and (module == 'math' or module.startswith('math.')):
                hit(7, node)
            if fact_path and module.split('.')[0] in ('locale', 'zoneinfo'):
                hit(8, node)
            if path not in RUNNER and any(module == d or module.startswith(d + '.') for d in DENIED):
                hit(14, node)
    if isinstance(node, (ast.Attribute, ast.Name)) and path not in RUNNER and any(name in ('os.environ', 'os.environb') for name in possible_names(node, origins)):
        hit(9, node)
    if not isinstance(node, ast.Call):
        return tuple(sorted(findings))
    for called in possible_names(node.func, origins):
        short = called.split('.')[-1]
        if short in ('get', 'setdefault', 'defaultdict') or (short == 'pop' and (
                len(node.args) > 1 or any(keyword.arg == 'default' for keyword in node.keywords))):
            hit(3, node)
        if short == 'CheckResult' and (path != 'atlas_brain/kernel/verdict.py' or not in_verdict):
            hit(4, node)
        if fact_path and (short == 'float' or called.startswith('math.')):
            hit(7, node)
        if fact_path and (called.startswith(('locale.', 'zoneinfo.')) or short in ('strptime', 'strftime', 'astimezone')):
            hit(8, node)
        if fact_path and called in ('time.localtime', 'time.tzset', 'time.ctime', 'time.asctime', 'datetime.datetime.fromtimestamp', 'datetime.date.fromtimestamp'):
            hit(8, node)
        if path not in RUNNER and (called in ('os.getenv', 'os.getenvb', 'time.time', 'time.time_ns', 'time.monotonic', 'time.perf_counter') or short in ('now', 'utcnow', 'today')):
            hit(9, node)
        if short in ('open', 'read_text', 'write_text'):
            unbound = called in ('open', 'builtins.open', 'io.open', '_io.open',
                                 'pathlib.Path.open', 'pathlib.PosixPath.open', 'pathlib.WindowsPath.open')
            mode_index = 1 if unbound else 0
            mode = next((value for index, value in enumerate(node.args) if index == mode_index), None)
            for keyword in node.keywords:
                if keyword.arg == 'mode':
                    mode = keyword.value
            binary = short == 'open' and isinstance(mode, ast.Constant) and isinstance(mode.value, str) and 'b' in mode.value
            encoding = any(k.arg == 'encoding' and not (isinstance(k.value, ast.Constant) and k.value.value is None) for k in node.keywords)
            if not binary and not encoding:
                hit(10, node)
        if called.startswith('re.') and short in ('compile', 'search', 'match', 'fullmatch', 'findall', 'finditer', 'split', 'sub', 'subn'):
            flag_index = 1 if short == 'compile' else 3 if short == 'split' else 4 if short in ('sub', 'subn') else 2
            positional = node.args[flag_index:flag_index + 1]
            if any(isinstance(argument, ast.Starred) for argument in node.args[:flag_index]):
                positional = []
            flags = list(positional) + [k.value for k in node.keywords if k.arg == 'flags']
            if not any(ascii_flag(f) for f in flags):
                hit(12, node)
            nonliteral = not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str)
            if nonliteral and not (pk_compiler_source and called == 're.compile' and in_pk_compiler):
                hit(12, node)
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and nested_unbounded(node.args[0].value):
                hit(12, node)
        if path != LOADER and called in ('importlib.import_module', '__import__', 'builtins.__import__'):
            hit(15, node)
    return tuple(sorted(findings))


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

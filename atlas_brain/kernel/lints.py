"""The fifteen static kernel guards frozen for the language spike (S3 3.3.1).

Scan the product tree, including uncalled functions. This conservative AST gate
complements strict typing and runtime admission; it is not a Python sandbox.
"""
import ast
import re
from hashlib import sha256

from .token_lints import bound_names, fallback_node

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


def lint(source: str, path: str) -> tuple[tuple[int, int], ...]:
    """Return sorted (rule number, source line) findings; syntax errors fail closed."""
    tree = ast.parse(source)
    parts = path.replace('\\', '/').split('/')
    fact_path = any(p in FACT_PATH for p in parts)
    fact_fields = 'model' in parts or 'packs' in parts
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f'{node.module}.{item.name}'

    def name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            if node.id not in aliases:
                return node.id
            return aliases[node.id]
        if isinstance(node, ast.Attribute):
            return name(node.value) + '.' + node.attr
        if isinstance(node, ast.Subscript):
            return name(node.value)
        return ''

    def tail(node: ast.AST) -> str:
        return name(node).split('.')[-1]

    def contains(node: ast.AST, names: tuple[str, ...]) -> bool:
        return any(tail(n) in names for n in ast.walk(node))

    rebound = {name(n) for n in ast.walk(tree) if isinstance(n, (ast.Name, ast.Attribute)) and isinstance(n.ctx, ast.Store)}
    for binding in ast.walk(tree):
        identifier = binding.arg if isinstance(binding, ast.arg) else binding.name if isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)) else ''
        if identifier:
            rebound.add(name(ast.Name(id=identifier, ctx=ast.Load())))
    rebound.update(name(ast.Name(id=k, ctx=ast.Load())) for k in bound_names(tree))
    assertions = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.Call) and name(n.func) == 'typing.assert_never' and name(n.func) not in rebound and 'typing' not in rebound)

    def ascii_flag(node: ast.AST) -> bool:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return ascii_flag(node.left) or ascii_flag(node.right)
        return name(node) in ('re.ASCII', 're.A') and name(node) not in rebound and 're' not in rebound

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def inside_verdict(node: ast.AST) -> bool:
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.FunctionDef) and node.name == 'verdict' and isinstance(parents[node], ast.Module):
                return True
        return False

    # PK compiles dynamic byte patterns, then checks its conservative grammar
    # before returning them. Only this reviewed source/function bypasses literals;
    # altered admission logic invalidates the receipt. ASCII checking still runs.
    pk_compiler_source = (path == 'atlas_brain/evidence/parsekit/patterns.py' and
                          sha256(source.encode('utf-8')).hexdigest() ==
                          '05f298e6c5be51774519d4bdea4c45ae21cfbf68fe98e9599af4cf3d855bc091')

    def inside_pk_compiler(node: ast.AST) -> bool:
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return (isinstance(node, ast.FunctionDef) and node.name == 'compile_pattern' and
                        isinstance(parents[node], ast.Module))
        return False

    findings: set[tuple[int, int]] = set()

    def hit(rule: int, node: ast.AST) -> None:
        findings.add((rule, node.lineno if isinstance(node, (ast.stmt, ast.expr, ast.ExceptHandler)) else 1))

    sets: set[str] = set()
    for node in ast.walk(tree):
        if fact_path and ((isinstance(node, ast.Constant) and not isinstance(node.value, (str, bytes, int, type(None), type(Ellipsis)))) or
                          (isinstance(node, ast.Name) and node.id == 'float')):
            hit(7, node)
        if isinstance(node, ast.AnnAssign) and contains(node.annotation, ('set', 'frozenset')) and isinstance(node.target, ast.Name):
            sets.add(node.target.id)
        if isinstance(node, ast.arg) and node.annotation and contains(node.annotation, ('set', 'frozenset')):
            sets.add(node.arg)
        if isinstance(node, (ast.Assign, ast.NamedExpr)):
            value = node.value
            if isinstance(value, (ast.Set, ast.SetComp)) or (isinstance(value, ast.Call) and tail(value.func) in ('set', 'frozenset')):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                sets.update(t.id for t in targets if isinstance(t, ast.Name))

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and fact_fields and (contains(node.annotation, ('Optional',)) or
                any(isinstance(n, ast.Constant) and n.value is None for n in ast.walk(node.annotation))):
            hit(1, node)
        if isinstance(node, ast.ClassDef):
            if any(tail(b) in STATES for b in node.bases):
                hit(13, node)
            record = any(tail(d.func if isinstance(d, ast.Call) else d) == 'dataclass' for d in node.decorator_list)
            if record:
                for field in node.body:
                    if isinstance(field, ast.AnnAssign) and field.value is not None and not contains(field.annotation, ('ClassVar',)):
                        hit(2, field)
        if fallback_node(node, name(node.func) if isinstance(node, ast.Call) else '', assertions=assertions):
            hit(3, node)
        if isinstance(node, ast.ExceptHandler) and (node.type is None or contains(node.type, ('BaseException',))):
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
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            iterator = node.iter
            if isinstance(iterator, (ast.Set, ast.SetComp)) or (isinstance(iterator, ast.Name) and iterator.id in sets) or (isinstance(iterator, ast.Call) and tail(iterator.func) in ('set', 'frozenset')):
                hit(11, node)
        if isinstance(node, (ast.Attribute, ast.Name)) and path not in RUNNER and name(node) in ('os.environ', 'os.environb'):
            hit(9, node)
        if not isinstance(node, ast.Call):
            continue
        called = name(node.func)
        short = tail(node.func)
        if short == 'CheckResult' and (path != 'atlas_brain/kernel/verdict.py' or not inside_verdict(node)):
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
            mode = node.args[mode_index] if len(node.args) > mode_index else None
            for keyword in node.keywords:
                if keyword.arg == 'mode':
                    mode = keyword.value
            binary = short == 'open' and isinstance(mode, ast.Constant) and isinstance(mode.value, str) and 'b' in mode.value
            encoding = any(k.arg == 'encoding' and not (isinstance(k.value, ast.Constant) and k.value.value is None) for k in node.keywords)
            if not binary and not encoding:
                hit(10, node)
        if called.startswith('re.') and short in ('compile', 'search', 'match', 'fullmatch', 'findall', 'finditer', 'split', 'sub', 'subn'):
            flags = list(node.args[1:] if short == 'compile' else node.args[2:]) + [k.value for k in node.keywords if k.arg == 'flags']
            if not any(ascii_flag(f) for f in flags):
                hit(12, node)
            nonliteral = not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str)
            if nonliteral and not (pk_compiler_source and called == 're.compile' and inside_pk_compiler(node)):
                hit(12, node)
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and nested_unbounded(node.args[0].value):
                hit(12, node)
        if path != LOADER and called in ('importlib.import_module', '__import__', 'builtins.__import__'):
            hit(15, node)
    for lineno, line in enumerate(source.splitlines(), 1):
        if re.search(r'#\s*pyright:\s*ignore\[', line, re.ASCII) and not re.search(r'reviewer:\s*\S', line, re.ASCII):
            findings.add((6, lineno))
    return tuple(sorted(findings))

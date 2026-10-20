"""The fifteen static kernel guards frozen for the language spike (S3 3.3.1).

Scan the product tree, including uncalled functions. This conservative AST gate
complements strict typing and runtime admission; it is not a Python sandbox.
"""
import ast
import re

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
        elif char in '*+' or (char == '{' and re.match(r'\{\d+,\}', pattern[index:], re.ASCII)):
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
            return aliases[node.id] if node.id in aliases else node.id
        if isinstance(node, ast.Attribute):
            return name(node.value) + '.' + node.attr
        return ''

    def tail(node: ast.AST) -> str:
        return name(node).split('.')[-1]

    def contains(node: ast.AST, names: tuple[str, ...]) -> bool:
        return any(tail(n) in names for n in ast.walk(node))

    findings: set[tuple[int, int]] = set()

    def hit(rule: int, node: ast.AST) -> None:
        findings.add((rule, getattr(node, 'lineno', 1)))

    sets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and contains(node.annotation, ('set', 'frozenset')):
            if isinstance(node.target, ast.Name):
                sets.add(node.target.id)
        if isinstance(node, ast.arg) and node.annotation and contains(node.annotation, ('set', 'frozenset')):
            sets.add(node.arg)
        if isinstance(node, (ast.Assign, ast.NamedExpr)):
            value = node.value
            if isinstance(value, (ast.Set, ast.SetComp)) or (isinstance(value, ast.Call) and tail(value.func) in ('set', 'frozenset')):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                sets.update(t.id for t in targets if isinstance(t, ast.Name))

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            if fact_fields and (contains(node.annotation, ('Optional',)) or
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
        if isinstance(node, (ast.If, ast.IfExp)) and node.orelse:
            test = node.test
            if any(isinstance(n, ast.Name) and 'token' in n.id.lower() for n in ast.walk(test)):
                hit(3, node)
        if isinstance(node, ast.ExceptHandler):
            broad = node.type is None or contains(node.type, ('BaseException',))
            if broad and path != 'atlas_brain/runner/__main__.py':
                hit(5, node)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or '']
            for module in modules:
                if fact_path and (module == 'math' or module.startswith('math.')):
                    hit(7, node)
                if fact_path and module.split('.')[0] in ('locale', 'zoneinfo'):
                    hit(8, node)
                if path not in RUNNER and any(module == d or module.startswith(d + '.') for d in DENIED):
                    hit(14, node)
        if isinstance(node, (ast.For, ast.comprehension)):
            iterator = node.iter
            if isinstance(iterator, (ast.Set, ast.SetComp)) or (isinstance(iterator, ast.Name) and iterator.id in sets) or (isinstance(iterator, ast.Call) and tail(iterator.func) in ('set', 'frozenset')):
                hit(11, node)
        if isinstance(node, ast.Attribute) and fact_path and name(node) in ('os.environ', 'os.environb'):
            hit(9, node)
        if not isinstance(node, ast.Call):
            continue
        called = name(node.func)
        short = tail(node.func)
        if short == 'get' and (len(node.args) > 1 or node.keywords):
            hit(3, node)
        if short == 'CheckResult' and path != 'atlas_brain/kernel/verdict.py':
            hit(4, node)
        if fact_path and (short == 'float' or called.startswith('math.')):
            hit(7, node)
        if fact_path and (called.startswith(('locale.', 'zoneinfo.')) or short in ('strptime', 'strftime', 'astimezone')):
            hit(8, node)
        if path not in RUNNER and (called in ('os.getenv', 'os.getenvb', 'time.time', 'time.time_ns') or short in ('now', 'utcnow', 'today')):
            hit(9, node)
        if short in ('open', 'read_text', 'write_text'):
            mode = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == 'mode':
                    mode = keyword.value
            binary = isinstance(mode, ast.Constant) and isinstance(mode.value, str) and 'b' in mode.value
            encoding = any(k.arg == 'encoding' and not (isinstance(k.value, ast.Constant) and k.value.value is None) for k in node.keywords)
            if not binary and not encoding:
                hit(10, node)
        if called.startswith('re.') and short in ('compile', 'search', 'match', 'fullmatch', 'findall', 'finditer', 'split', 'sub', 'subn'):
            flags = list(node.args[1:] if short == 'compile' else node.args[2:]) + [k.value for k in node.keywords if k.arg == 'flags']
            if not any(contains(f, ('ASCII', 'A')) for f in flags):
                hit(12, node)
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) and nested_unbounded(node.args[0].value):
                hit(12, node)
        if path != LOADER and called in ('importlib.import_module', '__import__', 'builtins.__import__'):
            hit(15, node)
    for lineno, line in enumerate(source.splitlines(), 1):
        if '# pyright:' in line and 'ignore[' in line and 'reviewer:' not in line:
            findings.add((6, lineno))
    return tuple(sorted(findings))

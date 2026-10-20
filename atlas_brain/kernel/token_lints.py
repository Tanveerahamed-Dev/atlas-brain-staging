"""Conservative AST refusal of implicit defaults in enumerated token maps.

Missing tokens must take the explicit unknown path. Even one-argument get
silently manufactures None, so token maps must use checked subscription.
This is a static shape guard, complemented by the closed parse-kit token map.
"""
import ast


def _tail(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return node.attr if isinstance(node, ast.Attribute) else ''


def _lookup_value(node: ast.AST) -> bool:
    return any(isinstance(part, ast.Subscript) and (
        isinstance(part.slice, (ast.Name, ast.Attribute)) or
        (isinstance(part.slice, ast.Constant) and type(part.slice.value) is str))
        for part in ast.walk(node))


def bound_names(node: ast.AST) -> frozenset[str]:
    return frozenset(part.name for part in ast.walk(node) if isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name) | frozenset(
        part.rest for part in ast.walk(node) if isinstance(part, ast.MatchMapping) and part.rest)


def _terminal_assertion(pattern: ast.pattern, body: list[ast.stmt], assertions: frozenset[ast.Call]) -> bool:
    bound = bound_names(pattern)
    if len(body) != 1 or not isinstance(body[0], ast.Expr):
        return False
    call = body[0].value
    return (isinstance(call, ast.Call) and call in assertions and
            len(call.args) == 1 and not call.keywords and
            isinstance(call.args[0], ast.Name) and call.args[0].id in bound)


def _literal_pattern(pattern: ast.pattern) -> bool:
    if isinstance(pattern, (ast.MatchValue, ast.MatchSingleton)):
        return True
    return isinstance(pattern, ast.MatchOr) and all(_literal_pattern(p) for p in pattern.patterns)


def _enum_comparison(node: ast.AST) -> bool:
    return any(isinstance(part, ast.Compare) and
        not any(isinstance(value, ast.Subscript) for value in ast.walk(part)) and any(
        isinstance(value, ast.Constant) and type(value.value) is str
        for value in ast.walk(part)) for part in ast.walk(node))


def _value_branch(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Assign, ast.AnnAssign, ast.Return))


def _returned_default(body: list[ast.stmt]) -> bool:
    while len(body) == 1 and isinstance(body[0], ast.If):
        body = body[0].orelse
    return bool(body) and isinstance(body[-1], ast.Return)


def fallback_node(node: ast.AST, called: str = '', *, assertions: frozenset[ast.Call] = frozenset()) -> bool:
    """Refuse defaults; assertion call witnesses require whole-module binding proof."""
    if isinstance(node, ast.Call):
        short = (called or _tail(node.func)).rsplit('.', 1)[-1]
        return short in ('get', 'setdefault', 'defaultdict') or (
            short == 'pop' and (len(node.args) > 1 or bool(node.keywords)))
    if isinstance(node, ast.IfExp):
        return (_lookup_value(node.body) or _lookup_value(node.orelse) or
                _enum_comparison(node.test))
    if isinstance(node, ast.If) and node.orelse:
        return (_enum_comparison(node.test) and (_returned_default(node.orelse) or
                (_value_branch(node.body) and _value_branch(node.orelse)))) or any(_lookup_value(part.value)
                   for statement in node.body + node.orelse for part in ast.walk(statement)
                   if isinstance(part, (ast.Assign, ast.AnnAssign, ast.Return)) and part.value is not None)
    if isinstance(node, ast.Match):
        patterns = [case.pattern for case in node.cases]
        # An object class pattern is universal, including without a literal arm.
        if any(isinstance(p, ast.MatchClass) and _tail(p.cls) == 'object'
               for pattern in patterns for p in ast.walk(pattern)):
            return True
        return any(not _literal_pattern(case.pattern) and
                   not (isinstance(case.pattern, ast.MatchClass) and
                        _tail(case.pattern.cls) in ('Known', 'Absent', 'Unknown', 'NotApplicable')) and
                   not _terminal_assertion(case.pattern, case.body, assertions)
                   for case in node.cases)
    return False

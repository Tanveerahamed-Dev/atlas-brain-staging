"""Conservative AST refusal of implicit defaults in enumerated token maps.

Missing tokens must take the explicit unknown path. Even one-argument get
silently manufactures None, so token maps must use checked subscription.
This is a static shape guard, complemented by the closed parse-kit token map.
"""
import ast
from typing import cast


def _tail(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return node.attr if isinstance(node, ast.Attribute) else ''


def _lookup_value(node: ast.AST) -> bool:
    return any(isinstance(part, ast.Subscript) and (
        isinstance(part.slice, (ast.Name, ast.Attribute)) or
        (isinstance(part.slice, ast.Constant) and type(part.slice.value) is str))
        for part in ast.walk(node))


def _lookup_branch(body: list[ast.stmt]) -> bool:
    return any(_lookup_value(part.value)
               for statement in body for part in ast.walk(statement)
               if isinstance(part, (ast.Assign, ast.AnnAssign, ast.Return)) and part.value is not None)


def statement_context(tree: ast.AST) -> tuple[dict[ast.stmt, tuple[ast.stmt, ...]], frozenset[ast.AST]]:
    """Bind successors to blocks and retain potentially intercepting outer scopes.

    Handler dispatch and context-manager behavior are unproven. A function body
    starts its own execution scope; a try's else is outside its own handlers.
    """
    following: dict[ast.stmt, tuple[ast.stmt, ...]] = {}
    intercepted: set[ast.AST] = set()
    pending: list[tuple[ast.AST, bool]] = [(tree, False)]
    while pending:
        owner, protected = pending.pop()
        fields = tuple(ast.iter_fields(owner))
        protected = protected and not any(field == 'args' and isinstance(value, ast.AST) for field, value in fields)
        if protected:
            intercepted.add(owner)
        catching = any(field == 'handlers' and bool(value) for field, value in fields)
        finalizing = any(field == 'finalbody' and bool(value) for field, value in fields)
        managing = any(field == 'items' and bool(value) for field, value in fields)
        for field, value in fields:
            children: tuple[ast.AST, ...] = ()
            if isinstance(value, ast.AST):
                children = (value,)
            elif isinstance(value, list):
                children = tuple(child for child in cast(list[object], value) if isinstance(child, ast.AST))
            block = tuple(child for child in children if isinstance(child, ast.stmt))
            following.update((statement, block[index + 1:]) for index, statement in enumerate(block))
            blocked = protected or (field == 'body' and (catching or managing)) or (
                field in ('body', 'orelse', 'handlers') and finalizing)
            pending.extend((child, blocked) for child in children)
    return following, frozenset(intercepted)


def bound_names(node: ast.AST) -> frozenset[str]:
    return frozenset(part.name for part in ast.walk(node) if isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name) | frozenset(
        part.rest for part in ast.walk(node) if isinstance(part, ast.MatchMapping) and part.rest)


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        return node.id
    if isinstance(node, ast.Attribute):
        return _qualified(node.value, aliases) + '.' + node.attr
    return ''


def binding_proof(tree: ast.AST, aliases: dict[str, str], rebound: set[str], *, call_target: str = 'typing.assert_never') -> tuple[frozenset[ast.Call], frozenset[ast.MatchClass]]:
    """Verify names against the import/rebinding environment supplied by the scanner."""
    def symbol(identifier: str) -> str:
        if identifier in aliases:
            return aliases[identifier]
        return identifier

    shadowed = rebound | {symbol(k) for k in sorted(bound_names(tree))}

    def stable(name: str) -> bool:
        return not any(name == key or name.startswith(key + '.') or key.startswith(name + '.') for key in sorted(shadowed))

    calls = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.Call) and _qualified(n.func, aliases) == call_target and stable(_qualified(n.func, aliases)))
    closed = tuple('atlas_brain.kernel.states.' + state for state in ('Known', 'Absent', 'Unknown', 'NotApplicable'))
    facts = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.MatchClass) and _qualified(n.cls, aliases) in closed and stable(_qualified(n.cls, aliases)))
    return calls, facts


def _irrefutable(pattern: ast.pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable(pattern.pattern)
    return isinstance(pattern, ast.MatchOr) and any(_irrefutable(part) for part in pattern.patterns)


def _terminal_assertion(pattern: ast.pattern, body: list[ast.stmt], assertions: frozenset[ast.Call]) -> bool:
    bound = bound_names(pattern)
    if not _irrefutable(pattern) or len(body) != 1 or not isinstance(body[0], ast.Expr):
        return False
    call = body[0].value
    return (isinstance(call, ast.Call) and call in assertions and
            len(call.args) == 1 and not call.keywords and
            isinstance(call.args[0], ast.Name) and call.args[0].id in bound)


def _literal_pattern(pattern: ast.pattern, facts: frozenset[ast.MatchClass] = frozenset()) -> bool:
    if isinstance(pattern, (ast.MatchValue, ast.MatchSingleton)):
        return True
    return (isinstance(pattern, ast.MatchClass) and pattern in facts) or (
        isinstance(pattern, ast.MatchOr) and all(_literal_pattern(p, facts) for p in pattern.patterns))


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


def _finite_subject(test: ast.AST) -> str:
    if isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1 and isinstance(test.ops[0], ast.Eq):
        left, right = test.left, test.comparators[0]
        if isinstance(right, ast.Constant) and type(right.value) is str:
            return _qualified(left, {})
        if isinstance(left, ast.Constant) and type(left.value) is str:
            return _qualified(right, {})
    return ''


def _refusal_tail(following: tuple[ast.stmt, ...], subject: str, unknowns: frozenset[ast.Call]) -> bool:
    if not following:
        return False
    # Only further literal equalities on this same input may precede the refusal.
    # An early unconditional return, mutation or unrelated condition is unproven.
    if len(following) > 1 and (not subject or any(
            not isinstance(s, ast.If) or s.orelse or _finite_subject(s.test) != subject for s in following[:-1])):
        return False
    last = following[-1]
    return isinstance(last, ast.Raise) or (isinstance(last, ast.Return) and isinstance(last.value, ast.Call) and last.value in unknowns)


def fallback_node(node: ast.AST, called: str = '', *, assertions: frozenset[ast.Call] = frozenset(), facts: frozenset[ast.MatchClass] = frozenset(), following: tuple[ast.stmt, ...] = (), unknowns: frozenset[ast.Call] = frozenset(), allow_refusal: bool = False) -> bool:
    """Refuse defaults; assertion call witnesses require whole-module binding proof."""
    if isinstance(node, ast.Call):
        short = (called or _tail(node.func)).rsplit('.', 1)[-1]
        return short in ('get', 'setdefault', 'defaultdict') or (
            short == 'pop' and (len(node.args) > 1 or bool(node.keywords)))
    if isinstance(node, ast.IfExp):
        return (_lookup_value(node.body) or _lookup_value(node.orelse) or
                _enum_comparison(node.test))
    if isinstance(node, ast.If):
        lookup = _lookup_branch(node.body + node.orelse)
        if allow_refusal and not node.orelse and _refusal_tail(following, _finite_subject(node.test), unknowns):
            return False
        return (_enum_comparison(node.test) and (_returned_default(node.body) or _returned_default(node.orelse) or
                _returned_default(list(following)) or (_value_branch(node.body) and (not node.orelse or _value_branch(node.orelse))))) or lookup
    if isinstance(node, ast.Match):
        terminals = frozenset(case for case in node.cases if allow_refusal and case.guard is None
                             and _terminal_assertion(case.pattern, case.body, assertions))
        if any(not _literal_pattern(case.pattern, facts) and
               case not in terminals
               for case in node.cases):
            return True
        terminal = _returned_default(list(following)) or bool(following and isinstance(following[-1], ast.Raise))
        return terminal and not terminals and not (allow_refusal and _refusal_tail(following, _qualified(node.subject, {}), unknowns))
    return False


def fallback_nodes(tree: ast.AST, aliases: dict[str, str], rebound: set[str]) -> frozenset[ast.AST]:
    """Inspect statement successors and genuine Unknown bindings for whole-source use."""
    assertions, facts = binding_proof(tree, aliases, rebound)
    unknowns, _ = binding_proof(tree, aliases, rebound, call_target='atlas_brain.kernel.states.Unknown')
    following, intercepted = statement_context(tree)
    return frozenset(node for node in ast.walk(tree) if fallback_node(node,
        _qualified(node.func, aliases) if isinstance(node, ast.Call) else '', assertions=assertions, facts=facts,
        following=following[node] if isinstance(node, ast.stmt) and node in following else (), unknowns=unknowns,
        allow_refusal=node not in intercepted))

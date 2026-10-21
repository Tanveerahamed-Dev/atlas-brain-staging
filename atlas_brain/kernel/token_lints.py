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


def bound_names(node: ast.AST) -> frozenset[str]:
    return frozenset(part.name for part in ast.walk(node) if isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name) | frozenset(
        part.rest for part in ast.walk(node) if isinstance(part, ast.MatchMapping) and part.rest)


def binding_proof(tree: ast.AST, aliases: dict[str, str], rebound: set[str]) -> tuple[frozenset[ast.Call], frozenset[ast.MatchClass]]:
    """Verify names against the import/rebinding environment supplied by the scanner."""
    def symbol(identifier: str) -> str:
        if identifier in aliases:
            return aliases[identifier]
        return identifier

    def qualified(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return symbol(node.id)
        if isinstance(node, ast.Attribute):
            return qualified(node.value) + '.' + node.attr
        return ''

    shadowed = rebound | {symbol(k) for k in sorted(bound_names(tree))}

    def stable(name: str) -> bool:
        return not any(name == key or name.startswith(key + '.') or key.startswith(name + '.') for key in sorted(shadowed))

    calls = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.Call) and qualified(n.func) == 'typing.assert_never' and stable(qualified(n.func)))
    closed = tuple('atlas_brain.kernel.states.' + state for state in ('Known', 'Absent', 'Unknown', 'NotApplicable'))
    facts = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.MatchClass) and qualified(n.cls) in closed and stable(qualified(n.cls)))
    return calls, facts


def _token_subject(node: ast.AST) -> bool:
    return any(isinstance(part, ast.Name) and 'token' in part.id.lower()
               for part in ast.walk(node))


def _literal_pattern(pattern: ast.pattern) -> bool:
    if isinstance(pattern, (ast.MatchValue, ast.MatchSingleton)):
        return True
    return isinstance(pattern, ast.MatchOr) and all(_literal_pattern(p) for p in pattern.patterns)


def fallback_node(node: ast.AST, called: str = '') -> bool:
    """True means rule 3 must refuse this node; no code under scan executes."""
    if isinstance(node, ast.Call):
        short = (called or _tail(node.func)).rsplit('.', 1)[-1]
        return short in ('get', 'setdefault', 'defaultdict') or (
            short == 'pop' and (len(node.args) > 1 or bool(node.keywords)))
    if isinstance(node, (ast.If, ast.IfExp)):
        return bool(node.orelse) and _token_subject(node.test)
    if isinstance(node, ast.Match):
        patterns = [case.pattern for case in node.cases]
        # An object class pattern is universal, including without a literal arm.
        if any(isinstance(p, ast.MatchClass) and _tail(p.cls) == 'object'
               for pattern in patterns for p in ast.walk(pattern)):
            return True
        enumerated = _token_subject(node.subject) or any(
            isinstance(p, (ast.MatchValue, ast.MatchSingleton))
            for pattern in patterns for p in ast.walk(pattern))
        return enumerated and any(not _literal_pattern(pattern) for pattern in patterns)
    return False

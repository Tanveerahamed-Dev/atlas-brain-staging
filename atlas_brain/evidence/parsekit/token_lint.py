"""Static guard for token handlers; arbitrary fallbacks must not map evidence."""
import ast


def _unknown(call: ast.expr | None) -> bool:
    return (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == "Unknown")


def _unknown_only(statements: list[ast.stmt]) -> bool:
    return bool(statements) and all(
        isinstance(stmt, ast.Raise)
        or (isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Return)) and _unknown(stmt.value))
        for stmt in statements
    )


def lint_token_handler(source: str) -> tuple[tuple[int, str], ...]:
    """Return deterministic diagnostics; parse source as data, never import it.

    This deliberately narrow handler grammar permits exact comparisons and
    closed-dict membership. Otherwise token containment, convenience lookups
    and catch-all branches are refused unless they explicitly produce Unknown
    or raise. The rule engine admits only the sealed TokenMap implementation.
    """
    tree = ast.parse(source)
    assignments: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
    # Permit membership only in variables assigned a dict on every assignment.
    tables = {name for name, values in assignments.items() if all(
        isinstance(value, ast.Dict) or (isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name) and value.func.id == "dict")
        for value in values
    )}
    failures: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("get", "setdefault", "startswith", "endswith", "find", "index")):
            failures.add((node.lineno, "token_convenience_lookup"))
        if isinstance(node, ast.Compare):
            for operator, right in zip(node.ops, node.comparators, strict=True):
                if isinstance(operator, (ast.In, ast.NotIn)) and not (
                    isinstance(right, ast.Name) and right.id in tables
                ):
                    failures.add((node.lineno, "token_substring_test"))
        branches: list[list[ast.stmt]] = []
        if isinstance(node, ast.If) and node.orelse:
            branches.append(node.orelse)
        if isinstance(node, ast.ExceptHandler):
            branches.append(node.body)
        if isinstance(node, ast.Match):
            for case in node.cases:
                if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                    branches.append(case.body)
        if any(not _unknown_only(branch) for branch in branches):
            failures.add((node.lineno, "token_catchall"))
        if isinstance(node, ast.IfExp) and not _unknown(node.orelse):
            failures.add((node.lineno, "token_catchall"))
    return tuple(sorted(failures))

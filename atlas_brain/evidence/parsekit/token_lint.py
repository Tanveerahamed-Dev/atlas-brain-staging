"""AST token policy: strict mapper rules plus owned-source escape auditing."""
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


def _scalar(value: ast.expr | None) -> bool:
    if isinstance(value, ast.Constant):
        return value.value is not None
    if isinstance(value, ast.Attribute):
        return value.attr.isupper() and not (isinstance(value.value, ast.Name) and value.value.id == "IntegrityState"
                    and value.attr in ("ERROR", "EMPTY", "UNKNOWN_FORMAT", "UNVERIFIED_PROMPT", "PAGING_ARTIFACTS"))
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "Known":
        return any(key.arg == "value" and _scalar(key.value) for key in value.keywords)
    return False


def lint_token_handler(source: str, *, structural: bool = False) -> tuple[tuple[int, str], ...]:
    """Audit source as data. Structural mode keeps byte-grammar operations.
    Source units get escape checks; the sealed mapper gets strict branches.
    Only EvidenceRef helpers may slice raw span bytes.
    """
    tree = ast.parse(source)
    assignments: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id not in assignments:
                        assignments[target.id] = []
                    assignments[target.id].append(node.value)
    tables = {name for name, values in assignments.items() if all(
        isinstance(value, ast.Dict) or (isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name) and value.func.id == "dict") for value in values
    )}
    raw_names = {name for name, values in assignments.items() if any(
        isinstance(value, ast.Attribute) and value.attr == "raw" for value in values
    )}
    raw_names.update(n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)
                     and (n.arg == "token" or (isinstance(n.annotation, ast.Name) and n.annotation.id == "str")))
    fallback_names = {name for name, values in assignments.items() if any(_scalar(value) for value in values)}
    for _ in assignments:
        for name, values in assignments.items():
            if any(isinstance(value, ast.Name) and value.id in raw_names for value in values):
                raw_names.add(name)
            if any(isinstance(value, ast.Name) and value.id in fallback_names for value in values):
                fallback_names.add(name)
    span_slices: set[ast.AST] = set()
    if structural:
        for func in ast.walk(tree):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(func.returns, ast.Name) and func.returns.id == "EvidenceRef":
                span_slices.update(n for n in ast.walk(func) if isinstance(n, ast.Subscript)
                                   and isinstance(n.slice, ast.Slice) and isinstance(n.slice.lower, ast.Attribute)
                                   and isinstance(n.slice.upper, ast.Attribute) and n.slice.lower.attr == "start"
                                   and n.slice.upper.attr == "end" and ast.dump(n.slice.lower.value) == ast.dump(n.slice.upper.value))
    failures: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and (
            node.args.defaults or any(value is not None for value in node.args.kw_defaults)
        ):
            failures.add((node.lineno, "token_parameter_default"))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for index, statement in enumerate(node.body):
                if isinstance(statement, ast.Return) and not _unknown(statement.value) and (
                    _scalar(statement.value) if structural else
                    isinstance(statement.value, (ast.Constant, ast.Attribute))
                    or any(isinstance(child, ast.Return) for prior in node.body[:index] for child in ast.walk(prior))
                ):
                    failures.add((statement.lineno, "token_catchall"))
        if isinstance(node, ast.Attribute) and (
            node.attr in ("get", "setdefault", "pop") or (node.attr in ("startswith", "endswith", "find", "index")
            and (not structural or (isinstance(node.value, ast.Attribute) and node.value.attr == "raw")
                 or (isinstance(node.value, ast.Name) and node.value.id in raw_names)))
        ):
            failures.add((node.lineno, "token_convenience_lookup"))
        if structural and isinstance(node, ast.Call):
            arguments = [*node.args, *(kw.value for kw in node.keywords if not (
                kw.arg == "basis" and isinstance(node.func, ast.Name) and node.func.id == "Known"
                and isinstance(kw.value, ast.Attribute) and kw.value.attr == "OBSERVED"
                and isinstance(kw.value.value, ast.Name) and kw.value.value.id == "Basis"))]
            arguments = [part for value in arguments for part in (
                value.value.elts if isinstance(value, ast.Starred) and isinstance(value.value, (ast.Tuple, ast.List)) else [value])]
            raw_input = any((isinstance(child, ast.Attribute) and child.attr == "raw")
                            or (isinstance(child, ast.Name) and child.id in raw_names)
                            for value in arguments for child in ast.walk(value))
            if raw_input and any(_scalar(value) or (isinstance(value, ast.Name) and value.id in fallback_names)
                                 for value in arguments):
                failures.add((node.lineno, "token_fallback_argument"))
        if isinstance(node, ast.Name) and node.id in ("getattr", "vars", "__getattribute__", "eval", "exec"):
            failures.add((node.lineno, "token_unproved_lookup"))
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Name) and node.value.id in fallback_names:
            failures.add((node.lineno, "token_catchall"))
        if isinstance(node, ast.Lambda) and _scalar(node.body):
            failures.add((node.lineno, "token_catchall"))
        if isinstance(node, ast.Subscript) and node not in span_slices and (
            isinstance(node.slice, ast.Slice) or (isinstance(node.value, ast.Name) and node.value.id in raw_names)
            or (isinstance(node.value, ast.Attribute) and node.value.attr == "raw")
        ):
            failures.add((node.lineno, "token_substring_test"))
        if isinstance(node, ast.Compare):
            for operator, right in zip(node.ops, node.comparators, strict=True):
                if isinstance(operator, (ast.In, ast.NotIn)) and (
                    isinstance(right, ast.Constant) or (isinstance(right, ast.Name) and right.id in raw_names)
                    if structural else not (isinstance(right, ast.Name) and right.id in tables)
                ):
                    failures.add((node.lineno, "token_substring_test"))
        branches: list[list[ast.stmt]] = []
        if isinstance(node, ast.If) and node.orelse:
            branches.append(node.orelse)
        if isinstance(node, ast.ExceptHandler):
            branches.append(node.body)
        if isinstance(node, ast.Match):
            branches.extend(case.body for case in node.cases if any(
                isinstance(pattern, ast.MatchAs) and pattern.pattern is None for pattern in ast.walk(case.pattern)))
        if isinstance(node, (ast.If, ast.ExceptHandler, ast.Match)) and any(
            not _unknown_only(branch) and (not structural or any(
                isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Return)) and _scalar(stmt.value) for stmt in branch
            )) for branch in branches
        ):
            failures.add((node.lineno, "token_catchall"))
        if isinstance(node, ast.IfExp) and not _unknown(node.orelse) and (not structural or _scalar(node.orelse)):
            failures.add((node.lineno, "token_catchall"))
    return tuple(sorted(failures))

"""AST token policy: strict mapper rules plus owned-source escape auditing."""
import ast


def _unknown(call: ast.expr | None) -> bool:
    return isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "Unknown"


def _unknown_only(statements: list[ast.stmt]) -> bool:
    return bool(statements) and all(isinstance(stmt, ast.Raise) or
        (isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Return)) and _unknown(stmt.value)) for stmt in statements)


def _scopes(tree: ast.AST) -> list[tuple[list[ast.AST], dict[str, list[ast.expr]], list[ast.arg], set[str], set[str]]]:
    frames = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    all_nodes = list(ast.walk(tree))
    parents = {child: node for node in all_nodes for child in ast.iter_child_nodes(node)}

    def owner(node: ast.AST) -> ast.AST:
        while node in parents:
            node = parents[node]
            if isinstance(node, frames):
                return node
        return tree

    scopes = [tree, *(node for node in all_nodes if isinstance(node, frames))]
    result: list[tuple[list[ast.AST], dict[str, list[ast.expr]], list[ast.arg], set[str], set[str]]] = []
    for scope in scopes:
        chain = [scope]
        while chain[-1] is not tree:
            parent = owner(chain[-1])
            while isinstance(parent, ast.ClassDef):
                parent = owner(parent)
            chain.append(parent)
        bindings: dict[str, list[ast.expr]] = {}
        parameters: dict[str, ast.arg] = {}
        unknowns: set[str] = set()
        passthroughs: set[str] = set()
        for frame in reversed(chain):
            local: dict[str, list[ast.expr]] = {}
            for node in all_nodes:
                if owner(node) is not frame:
                    continue
                if isinstance(node, ast.arg):
                    parameters[node.arg] = node
                    unknowns.discard(node.arg)
                    passthroughs.discard(node.arg)
                    if node.arg in bindings:
                        del bindings[node.arg]
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    for target in node.targets if isinstance(node, ast.Assign) else (node.target,):
                        if isinstance(target, ast.Name):
                            local[target.id] = [*local[target.id], node.value] if target.id in local else [node.value]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    unknowns.discard(node.name)
                    passthroughs.discard(node.name)
                    if isinstance(node, ast.FunctionDef) and not node.decorator_list and len(node.body) == 1:
                        returned = node.body[0]
                        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                        if isinstance(returned, ast.Return) and isinstance(returned.value, ast.Name) and any(
                            argument.arg == returned.value.id for argument in args
                        ):
                            passthroughs.add(node.name)
                    if isinstance(node, ast.FunctionDef) and not node.decorator_list and _unknown_only(node.body):
                        unknowns.add(node.name)
            bindings.update(local)
            unknowns.difference_update(local)
            passthroughs.difference_update(local)
        nodes = [node for node in all_nodes if node is scope or (owner(node) is scope and not isinstance(node, frames))]
        result.append((nodes, bindings, list(parameters.values()), unknowns, passthroughs))
    return result


def _scalar_expression(value: ast.expr | None, proof: dict[str, set[str]]) -> bool:
    if isinstance(value, ast.Constant):
        return value.value is not None
    if isinstance(value, ast.Name):
        return value.id in proof["fallbacks"]
    if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name) and value.value.id in proof["data"] | proof["tables"]:
        return False
    if isinstance(value, ast.Attribute):
        if isinstance(value.value, ast.Name) and value.value.id in proof["mapped"]:
            return False
        if value.attr == "raw" and value.attr not in proof["fallbacks"]:
            receiver = value.value
            while isinstance(receiver, (ast.Attribute, ast.Subscript)):
                receiver = receiver.value
            return not (isinstance(receiver, ast.Name) and receiver.id in proof["observed"] and receiver.id not in proof["fallbacks"])
        return not (isinstance(value.value, ast.Name) and value.value.id == "IntegrityState"
                    and value.attr in ("ERROR", "EMPTY", "UNKNOWN_FORMAT", "UNVERIFIED_PROMPT", "PAGING_ARTIFACTS"))
    if _unknown(value):
        return False
    if isinstance(value, ast.Call):
        if isinstance(value.func, ast.Attribute) and (isinstance(value.func.value, ast.Attribute) and value.func.value.attr == "raw"
                or isinstance(value.func.value, ast.Name) and value.func.value.id in proof["raw"]):
            return True
        if isinstance(value.func, ast.Name):
            if value.func.id in proof["unknowns"] or value.func.id == "EvidenceRef":
                return False
            if value.func.id == "Known":
                return any(key.arg == "value" and _scalar_expression(key.value, proof) for key in value.keywords)
            if value.func.id == "Captured":
                return any(_scalar_expression(part, proof) for part in value.args[2:3]) or any(
                    key.arg == "value" and _scalar_expression(key.value, proof) for key in value.keywords)
        if isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name) and value.args and not _scalar_expression(value.args[0], proof) and (
            value.func.attr == "resolve" and value.func.value.id in proof["maps"] or
            value.func.attr in ("fullmatch", "match", "search") and value.func.value.id in proof["patterns"] and (isinstance(value.args[0], ast.Name) and value.args[0].id in proof["data"] or isinstance(value.args[0], ast.Subscript) and isinstance(value.args[0].value, ast.Name) and value.args[0].value.id in proof["data"])
        ):
            return False
        parts = [*value.args, *(key.value for key in value.keywords)]
        if isinstance(value.func, ast.Attribute):
            parts.append(value.func.value)
        return all(_scalar_expression(part, proof) for part in parts)
    if value is None:
        return False
    return any(_scalar_expression(child, proof) for child in ast.iter_child_nodes(value) if isinstance(child, ast.expr))


def _check_unit(nodes: list[ast.AST], assignments: dict[str, list[ast.expr]], parameters: list[ast.arg],
                unknowns: set[str], passthroughs: set[str], structural: bool) -> set[tuple[int, str]]:
    tables = {name for name, values in assignments.items() if all(isinstance(value, ast.Dict) or
        (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "dict") for value in values)}
    raw_names = {name for name, values in assignments.items() if any(
        isinstance(value, ast.Attribute) and value.attr == "raw" for value in values)}
    raw_names.update(n.arg for n in parameters if n.arg == "token" or
                     isinstance(n.annotation, ast.Name) and n.annotation.id == "str")
    buffers = {n.arg for n in parameters if n.arg != "token" and n.arg not in assignments and isinstance(n.annotation, ast.Name) and n.annotation.id == "bytes"}
    proof: dict[str, set[str]] = {"fallbacks": set(), "observed": set(assignments) | {n.arg for n in parameters}, "buffers": buffers,
             "data": set(buffers), "raw": raw_names, "maps": set(), "patterns": set(), "mapped": set(), "tables": tables, "unknowns": unknowns, "passthroughs": set(passthroughs)}

    def scalar(value: ast.expr | None) -> bool:
        return _scalar_expression(value, proof)

    for _ in range(len(assignments) + 1):
        for name, values in assignments.items():
            if all(isinstance(value, ast.Name) and value.id in proof["passthroughs"] for value in values):
                proof["passthroughs"].add(name)
            for key, factory, method in (("maps", "TokenMap", "closed"), ("patterns", "compile_pattern", "")):
                if factory not in assignments and factory not in {n.arg for n in parameters} and all(
                    isinstance(value, ast.Name) and value.id in proof[key] or isinstance(value, ast.Call) and (
                    isinstance(value.func, ast.Name) and not method and value.func.id == factory or
                    isinstance(value.func, ast.Attribute) and value.func.attr == method and
                    isinstance(value.func.value, ast.Name) and value.func.value.id == factory) for value in values):
                    proof[key].add(name)
            for key, origins, methods in (("mapped", "maps", ("resolve",)), ("data", "patterns", ("fullmatch", "match", "search"))):
                if all(isinstance(value, ast.Name) and value.id in proof[key] or isinstance(value, ast.Call) and value.args and not scalar(value.args[0]) and
                    isinstance(value.func, ast.Attribute) and value.func.attr in methods and
                    isinstance(value.func.value, ast.Name) and value.func.value.id in proof[origins] and (origins == "maps" or isinstance(value.args[0], ast.Name) and value.args[0].id in proof["data"] or isinstance(value.args[0], ast.Subscript) and isinstance(value.args[0].value, ast.Name) and value.args[0].value.id in proof["data"]) for value in values):
                    proof[key].add(name)
            if all(isinstance(value, ast.Name) and value.id in buffers or isinstance(value, ast.Subscript) and
                   isinstance(value.value, ast.Name) and value.value.id in buffers for value in values):
                buffers.add(name)
                proof["data"].add(name)
            if any(isinstance(value, ast.Name) and value.id in raw_names or isinstance(value, ast.Call) and
                   isinstance(value.func, ast.Attribute) and value.func.attr == "decode" and isinstance(value.func.value, ast.Subscript)
                   and isinstance(value.func.value.value, ast.Name) and value.func.value.value.id in proof["data"] for value in values):
                raw_names.add(name)
            if any(scalar(value) for value in values):
                proof["fallbacks"].add(name)
    span_slices: set[ast.AST] = set()
    if structural:
        for func in nodes:
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(func.returns, ast.Name) and func.returns.id == "EvidenceRef":
                span_slices.update(n for n in ast.walk(func) if isinstance(n, ast.Subscript)
                                   and isinstance(n.slice, ast.Slice) and isinstance(n.slice.lower, ast.Attribute)
                                   and isinstance(n.slice.upper, ast.Attribute) and n.slice.lower.attr == "start"
                                   and n.slice.upper.attr == "end" and ast.dump(n.slice.lower.value) == ast.dump(n.slice.upper.value))
    refusal_tests: set[ast.AST] = set()
    for branch in nodes:
        if isinstance(branch, ast.If) and all(isinstance(stmt, ast.Raise) or isinstance(stmt, ast.Return) and
            isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and
            stmt.value.func.id in {"Unknown", *unknowns} for stmt in branch.body):
            refusal_tests.update(ast.walk(branch.test))
    failures: set[tuple[int, str]] = set()
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and (
            node.args.defaults or any(value is not None for value in node.args.kw_defaults)
        ):
            failures.add((node.lineno, "token_parameter_default"))
        if not structural and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for index, statement in enumerate(node.body):
                if isinstance(statement, ast.Return) and not _unknown(statement.value) and (
                    isinstance(statement.value, (ast.Constant, ast.Attribute))
                    or any(isinstance(child, ast.Return) for prior in node.body[:index] for child in ast.walk(prior))
                ):
                    failures.add((statement.lineno, "token_catchall"))
        if isinstance(node, ast.Attribute) and node.attr in ("get", "setdefault", "pop"):
            failures.add((node.lineno, "token_convenience_lookup"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("Known", "Captured") and scalar(node):
            failures.add((node.lineno, "token_catchall"))
        if structural and node not in refusal_tests and isinstance(node, ast.Call) and not _unknown(node) and not (
            isinstance(node.func, ast.Name) and node.func.id in {"Known", "Captured", "EvidenceRef", *proof["unknowns"]}
        ):
            arguments = [*node.args, *(kw.value for kw in node.keywords)]
            arguments = [part for value in arguments for part in (
                value.value.elts if isinstance(value, ast.Starred) and isinstance(value.value, (ast.Tuple, ast.List)) else [value])]
            raw_input = any((isinstance(child, ast.Attribute) and child.attr == "raw")
                            or (isinstance(child, ast.Name) and child.id in raw_names)
                            for value in arguments for child in ast.walk(value))
            proved_call = (isinstance(node.func, ast.Name) and node.func.id in proof["passthroughs"] or
                           isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                           and node.func.attr == "resolve" and node.func.value.id in proof["maps"])
            if raw_input and (any(scalar(value) for value in arguments) or not proved_call):
                failures.add((node.lineno, "token_fallback_argument"))
        if isinstance(node, ast.Name) and node.id in ("getattr", "vars", "__getattribute__", "eval", "exec"):
            failures.add((node.lineno, "token_unproved_lookup"))
        if isinstance(node, ast.Return) and (
            ((structural or isinstance(node.value, ast.Call)) and scalar(node.value))
            or (isinstance(node.value, ast.Name) and node.value.id in proof["fallbacks"])
        ):
            failures.add((node.lineno, "token_catchall"))
        if isinstance(node, ast.Lambda) and scalar(node.body):
            failures.add((node.lineno, "token_catchall"))
        if isinstance(node, ast.Subscript) and node not in span_slices and not (
            structural and isinstance(node.value, ast.Name) and node.value.id in proof["buffers"]
        ) and (
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
        if not structural and isinstance(node, (ast.If, ast.ExceptHandler, ast.Match)) and any(
            not _unknown_only(branch) for branch in branches
        ):
            failures.add((node.lineno, "token_catchall"))
        if not structural and isinstance(node, ast.IfExp) and not _unknown(node.orelse):
            failures.add((node.lineno, "token_catchall"))
    return failures


def lint_token_handler(source: str, *, structural: bool = False) -> tuple[tuple[int, str], ...]:
    """Audit lexical source units; permit proved byte grammar and closed maps."""
    failures: set[tuple[int, str]] = set()
    for nodes, assignments, parameters, unknowns, passthroughs in _scopes(ast.parse(source)):
        failures.update(_check_unit(nodes, assignments, parameters, unknowns, passthroughs, structural))
    return tuple(sorted(failures))

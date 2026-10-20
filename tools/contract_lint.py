"""Reject computations in contract source; identity/membership validate wire shape."""
import ast
import sys
from pathlib import Path

DENIED = {"sum", "min", "max", "len", "abs", "round", "pow", "divmod",
          "math", "operator", "statistics", "functools", "Counter", "count",
          "eval", "exec", "__import__", "getattr", "__add__", "__sub__", "__mul__",
          "__truediv__", "__floordiv__", "__pow__", "__mod__"}


def violations(source: str) -> list[int]:
    tree = ast.parse(source)
    annotations = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.AnnAssign, ast.arg)):
            annotations.update(ast.walk(node.annotation)) if node.annotation else None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            annotations.update(ast.walk(node.returns))
        if isinstance(node, ast.TypeAlias):
            annotations.update(ast.walk(node.value))
    bad = []
    for node in ast.walk(tree):
        if node in annotations and isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            continue
        arithmetic = isinstance(node, (ast.BinOp, ast.AugAssign))
        # Literal signed integers are declarations, not computed facts.
        unary = isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert))
        literal = unary and isinstance(node.op, (ast.USub, ast.UAdd)) and isinstance(node.operand, ast.Constant) and type(node.operand.value) is int
        compare = isinstance(node, ast.Compare) and any(
            isinstance(op, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in node.ops)
        name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
        imported = isinstance(node, ast.Import) and any(a.name.split(".")[0] in DENIED for a in node.names)
        imported_from = isinstance(node, ast.ImportFrom) and (
            (node.module or "").split(".")[0] in DENIED or any(a.name in DENIED for a in node.names))
        if arithmetic or (unary and not literal) or compare or name in DENIED or imported or imported_from:
            bad.append(node.lineno)
    return sorted(set(bad))


if __name__ == "__main__":
    paths = list(map(Path, sys.argv[1:])) or list(Path("atlas_brain/contract").rglob("*.py"))
    failures = [(p, line) for p in paths
        for line in violations(p.read_text(encoding="utf-8"))]
    for path, line in failures:
        print(f"{path.as_posix()}:{line}: contract computation refused")
    raise SystemExit(int(bool(failures)))

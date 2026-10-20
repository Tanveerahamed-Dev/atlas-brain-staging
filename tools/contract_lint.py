"""Reject computations in contract source; identity/membership validate wire shape."""
import ast
from pathlib import Path

DENIED = {"sum", "min", "max", "len", "abs", "round", "pow", "divmod",
          "math", "operator", "statistics", "functools", "Counter"}


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
        if node in annotations:
            continue
        arithmetic = isinstance(node, (ast.BinOp, ast.AugAssign))
        # Literal signed integers are declarations, not computed facts.
        unary = isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd))
        literal = unary and isinstance(node.operand, ast.Constant) and type(node.operand.value) is int
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
    raise SystemExit(int(any(violations(p.read_text(encoding="utf-8"))
        for p in Path("atlas_brain/contract").rglob("*.py"))))

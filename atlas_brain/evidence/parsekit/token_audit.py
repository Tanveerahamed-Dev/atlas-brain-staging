"""Fail-closed census of every owned pack/adapter source unit and TokenMap."""
import ast
from dataclasses import dataclass
from pathlib import Path

from .token_lint import lint_token_handler


@dataclass(frozen=True, slots=True)
class SourceAudit:
    expected: tuple[str, ...]
    audited: tuple[str, ...]
    findings: tuple[tuple[str, int, str], ...]


class SourceVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source: str, strict: bool) -> None:
        self.path, self.source, self.strict = path, source, strict
        self.audited: list[str] = []
        self.findings: set[tuple[str, int, str]] = set()

    def audit(self, node: ast.AST, line: int, name: str) -> None:
        text = self.source if isinstance(node, ast.Module) else ast.get_source_segment(self.source, node)
        if text is None:
            raise ValueError("unscanned source unit")
        self.audited.append(f"{self.path}:{line}:{name}")
        context = text if self.strict else self.source
        offset = line - 1 if self.strict else 0
        self.findings.update((self.path, offset + row, code)
                             for row, code in lint_token_handler(context, structural=not self.strict))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.audit(node, node.lineno, node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.audit(node, node.lineno, node.name)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.audit(node, node.lineno, f"lambda@{node.col_offset}")
        self.generic_visit(node)


def audit_tree(root: Path) -> SourceAudit:
    core = root / "evidence/parsekit/rules.py"
    paths = [core]
    for name in ("packs", "platform"):
        base = root / name
        if base.is_symlink():
            raise ValueError("unscanned linked source")
        for path in base.rglob("*"):
            if path.is_symlink():
                raise ValueError("unscanned linked source")
            if path.is_file() and path.suffix.lower() == ".py":
                paths.append(path)
    expected: list[str] = []
    audited: list[str] = []
    findings: set[tuple[str, int, str]] = set()
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("unscanned linked source")
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        scope: ast.AST = tree
        line, label = 1, "@module"
        if path == core:
            owners = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TokenMap"]
            if len(owners) != 1:
                raise ValueError("unscanned TokenMap owner")
            scope = owners[0]
            line, label = owners[0].lineno, "TokenMap"
        relative = path.relative_to(root).as_posix()
        expected.append(f"{relative}:{line}:{label}")
        for node in ast.walk(scope):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                name = f"lambda@{node.col_offset}" if isinstance(node, ast.Lambda) else node.name
                expected.append(f"{relative}:{node.lineno}:{name}")
        visitor = SourceVisitor(relative, source, path == core)
        visitor.audit(scope, line, label)
        visitor.visit(scope)
        audited.extend(visitor.audited)
        findings.update(visitor.findings)
    if sorted(expected) != sorted(audited) or len(set(audited)) != len(audited):
        raise ValueError("unscanned or duplicated owned handler")
    return SourceAudit(tuple(sorted(expected)), tuple(sorted(audited)), tuple(sorted(findings)))

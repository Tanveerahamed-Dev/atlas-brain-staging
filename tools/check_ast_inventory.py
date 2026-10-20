"""Check actual AST uses and source-fence admission; never execute K source.

This verifies source admission, not K's lint, type or kernel-freeze acceptance.
"""
import ast
import json
import subprocess

from tools.fence import SCOPED_API, source_allowed

SOURCES = {
    "atlas_brain/kernel/token_lints.py": "2d2e451e143371118bf62662b86aad32d1fb0193",
    "atlas_brain/kernel/lints.py": "a4e7f07ee17d0b8b0fd9dee6b0535c2279cedeb2",
}


def main() -> int:
    receipts = []
    sources = {path: subprocess.check_output(["git", "show", f"{revision}:{path}"], encoding="utf-8")
               for path, revision in SOURCES.items()}
    for path, revision in SOURCES.items():
        source = sources[path]
        used = {f"ast.{node.attr}" for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ast"}
        if used != SCOPED_API[path]:
            raise ValueError("AST admission differs from the approved request's actual uses")
        if not source_allowed(source, sources, path):
            raise ValueError("K source fails the amended source-admission gate")
        receipts.append({"path": path, "source_head": revision, "apis": sorted(used), "source_fence": "allowed"})
    print(json.dumps({"ast_inventory": receipts, "unique_apis": len(set().union(*SCOPED_API.values()))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

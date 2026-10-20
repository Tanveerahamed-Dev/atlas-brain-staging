"""Check the pinned request's actual AST API uses; never execute K source.

This verifies the admission inventory, not K's whole-source or lint acceptance.
"""
import ast
import json
import subprocess

from tools.fence import SCOPED_API

SOURCES = {
    "atlas_brain/kernel/token_lints.py": "2d2e451e143371118bf62662b86aad32d1fb0193",
    "atlas_brain/kernel/lints.py": "31d0f5450efdd4896452d3f5bfed94e7d859c2b1",
}


def main() -> int:
    receipts = []
    for path, revision in SOURCES.items():
        source = subprocess.check_output(["git", "show", f"{revision}:{path}"], encoding="utf-8")
        used = {f"ast.{node.attr}" for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ast"}
        if used != SCOPED_API[path]:
            raise ValueError("AST admission differs from the approved request's actual uses")
        receipts.append({"path": path, "source_head": revision, "apis": sorted(used)})
    print(json.dumps({"ast_inventory": receipts, "unique_apis": len(set().union(*SCOPED_API.values()))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

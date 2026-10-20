"""Check actual AST uses and source-fence admission; never execute K source.

This verifies source admission, not K's lint, type or kernel-freeze acceptance.
"""
import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.fence import SCOPED_API, source_allowed

SOURCES = {
    "atlas_brain/kernel/token_lints.py": "066b1ed8a767b1a3edd8b399e82afe264d33b3af",
    "atlas_brain/kernel/lints.py": "542d75f03d4f71a85d2c3397b5829e28e71a9ff0",
    "atlas_brain/evidence/parsekit/token_lint.py": "1b2661492e19387ba0bd602d085d0e93ee1ee177",
    "atlas_brain/evidence/parsekit/token_audit.py": "7082fec06a7253d028b359ada44423d2c0391587",
}


def tracked_borrowing_probe(sources):
    tool = str(Path(__file__).with_name("fence.py").resolve())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for path, source in sources.items():
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(source, encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", directory], check=True)
        subprocess.run(["git", "-C", directory, "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=root, check=True)
        plant = root / "atlas_brain/model/runtime.py"
        plant.parent.mkdir(parents=True)
        refusals = {}
        for label, source in (
            ("runtime_global_reexport", "from atlas_brain.kernel.lints import sha256; digest = sha256(raw)"),
            ("runtime_pk_global_reexport", "from atlas_brain.evidence.parsekit.token_audit import dataclass; dataclass(Record)"),
        ):
            plant.write_text(source + "\n", encoding="utf-8")
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            result = subprocess.run([sys.executable, tool], cwd=root, capture_output=True, text=True, check=False)
            if result.returncode != 1 or "scope fence: 1 refused" not in result.stdout:
                raise ValueError(f"real tracked-file gate accepted {label}")
            refusals[label] = "refused"
    return {"pinned_source_tree": "allowed", **refusals}


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
    print(json.dumps({"ast_inventory": receipts, "unique_apis": len(set().union(*SCOPED_API.values())),
                      "tracked_probe": tracked_borrowing_probe(sources)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Preserved contract computation plants and reflected-access refusals."""
import pytest

from tools.contract_lint import violations

@pytest.mark.parametrize("plant", ["x = a + b", "x += 1", "x = a * b",
    "x = -a", "x = a < b", "x = a == b", "x = sum(rows)",
    "x = min(rows)", "x = statistics.mean(rows)", "from operator import add",
    "import math", "f = sum", "from builtins import sum as fold",
    "x: a + b", "x: tuple[sum(rows)]", "type X = a + b", "x = ~a",
    "x = value.__add__(other)", "x = eval(source)", "x = ~1",
    "x = a in b", "x = a is b", "x = a not in b"])
def test_contract_lint_fires_on_each_planted_computation(plant):
    assert violations(plant)


def test_contract_tree_and_declarative_types_pass_lint():
    from pathlib import Path
    paths = list(Path("atlas_brain/contract").rglob("*.py"))
    assert paths
    for path in paths:
        assert not violations(path.read_text(encoding="utf-8")), path
    assert not violations("x: str | int\nLIMIT = -9007199254740991")


def test_planted_arithmetic_fails_real_lint_entrypoint(tmp_path):
    import subprocess
    import sys
    plant = tmp_path / "projection.py"
    plant.write_text("result = left + right", encoding="utf-8")
    result = subprocess.run([sys.executable, "tools/contract_lint.py", str(plant)],
        capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "computation refused" in result.stdout


@pytest.mark.parametrize("operation", ["add", "sub", "mul", "matmul", "truediv",
    "floordiv", "mod", "pow", "lshift", "rshift", "and", "or", "xor", "divmod"])
@pytest.mark.parametrize("prefix", ["", "r", "i"])
def test_arithmetic_protocol_family_is_refused(operation, prefix):
    assert violations(f"result = left.__{prefix}{operation}__(right)")
    assert violations(f"operation = left.__{prefix}{operation}__")


@pytest.mark.parametrize("operation", ["neg", "pos", "invert", "abs", "round", "divmod"])
def test_unary_and_numeric_protocol_calls_are_refused(operation):
    assert violations(f"result = value.__{operation}__()")


def test_workflow_concurrency_separates_main_pr_and_merge_group_heads():
    import re
    from pathlib import Path
    source = Path(".github/workflows/contract.yml").read_text(encoding="utf-8")
    group = re.search(r"^  group: (.+)$", source, re.MULTILINE).group(1)

    def distinct_heads(template):
        keys = {template.replace("${{ github.event_name }}", event).replace("${{ github.sha }}", sha)
            for event in ("push", "pull_request", "merge_group") for sha in ("head-a", "head-b")}
        return len(keys) == 6

    assert distinct_heads(group)
    assert not distinct_heads("ct-${{ github.workflow }}")  # Planted shared main key.
    assert not distinct_heads("ct-${{ github.sha }}")  # Planted cross-event collision.
    assert "  cancel-in-progress: false" in source
    assert "  pull_request:" in source and "  merge_group:" in source
    assert "  push:\n    branches: [main]" in source


@pytest.mark.parametrize("plant", [
    'left.__getattribute__("__add__")(right)',
    'object.__getattribute__(left, "__radd__")(right)',
    'type(left).__dict__["__add__"](left, right)',
    'vars(type(left))["__add__"](left, right)',
    'getattr(left, "__add__")(right)',
    'globals()["operation"](left, right)',
    'callbacks[0](left, right)',
    'factory()(left, right)',
    'from builtins import vars as reflect',
    'import inspect',
    'value._internal_operation(right)',
])
def test_reflected_arithmetic_fails_real_lint_entrypoint(tmp_path, plant):
    import subprocess
    import sys
    path = tmp_path / "projection.py"
    path.write_text(plant, encoding="utf-8")
    result = subprocess.run([sys.executable, "tools/contract_lint.py", str(path)],
        capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "computation refused" in result.stdout


def test_structural_source_passes_real_lint_entrypoint(tmp_path):
    import subprocess
    import sys
    path = tmp_path / "projection.py"
    path.write_text('result = "".join(map(str, values))', encoding="utf-8")
    assert subprocess.run([sys.executable, "tools/contract_lint.py", str(path)],
        capture_output=True, check=False).returncode == 0


def test_missing_contract_tree_fails_closed(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    script = Path("tools/contract_lint.py").resolve()
    result = subprocess.run([sys.executable, str(script)], cwd=tmp_path,
        capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "contract sources missing" in result.stdout

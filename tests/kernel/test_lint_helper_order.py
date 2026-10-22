"""The scanner's own helper must satisfy the ordinary iteration guard."""
from pathlib import Path

from atlas_brain.kernel.lints import lint


def test_fallback_helper_has_no_unordered_set_iteration():
    path = 'atlas_brain/kernel/token_lints.py'
    findings = lint(Path(path).read_text(encoding='utf-8'), path)
    assert not [location for rule, location in findings if rule == 11]

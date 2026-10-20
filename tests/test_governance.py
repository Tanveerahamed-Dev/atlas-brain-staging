import json
import subprocess

import pytest

from tools.governance import audit, diff_digest


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    commit(tmp_path, allow_empty=True)
    return tmp_path


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()


def commit(repo, allow_empty=False):
    git(repo, "add", ".")
    return git(repo, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
               "commit", "-qm", "synthetic", *(["--allow-empty"] if allow_empty else []))


def write(repo, name, text):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_size_boundary_and_generated_diff(repo):
    write(repo, "governance/generators.json", json.dumps({"uv.lock": {"command": "uv lock"}}))
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "tools/example.py", "# synthetic\n" * 400)
    write(repo, "uv.lock", "generated\n" * 500)
    write(repo, "fixtures/sample.txt", "synthetic\n" * 500)
    commit(repo)
    assert audit(repo, base, "HEAD")["counted_lines"] == 400
    digest = diff_digest(repo, base, "HEAD")
    write(repo, "uv.lock", "regenerated\n")
    commit(repo)
    assert diff_digest(repo, base, "HEAD") == digest
    write(repo, "tools/example.py", "# synthetic\n" * 401)
    commit(repo)
    with pytest.raises(ValueError, match="AD-03"):
        audit(repo, base, "HEAD")


@pytest.mark.parametrize("plant", ["self_exemption", "binary", "two_modules"])
def test_size_refuses_planted_bypasses(repo, plant):
    base = git(repo, "rev-parse", "HEAD")
    if plant == "self_exemption":
        write(repo, "governance/generators.json", json.dumps({"tools/example.py": {}}))
    elif plant == "binary":
        (repo / "blob.bin").write_bytes(bytes([0, 1, 2]))
    else:
        write(repo, "atlas_brain/kernel/a.py", "# synthetic\n")
        write(repo, "atlas_brain/model/b.py", "# synthetic\n")
    commit(repo)
    with pytest.raises(ValueError, match="AD-03"):
        audit(repo, base, "HEAD")


@pytest.mark.parametrize("plant", ["overlong", "edit_accepted", "delete_accepted"])
def test_adr_refuses_planted_violations(repo, plant):
    name = "docs/adr/0000-example.md"
    write(repo, name, "# Synthetic ADR\nStatus: accepted\nFrozen decision.\n")
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    if plant == "delete_accepted":
        (repo / name).unlink()
    else:
        write(repo, name, "line\n" * 61 if plant == "overlong" else "# Synthetic ADR\nStatus: accepted\nAltered.\n")
    commit(repo)
    with pytest.raises(ValueError, match="AD-07"):
        audit(repo, base, "HEAD")


def test_accepted_adr_status_only_change_passes(repo):
    name = "docs/adr/0000-example.md"
    write(repo, name, "# Synthetic ADR\nStatus: accepted\nFrozen decision.\n")
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    write(repo, name, "# Synthetic ADR\nStatus: superseded\nFrozen decision.\n")
    commit(repo)
    assert audit(repo, base, "HEAD")["counted_lines"] == 2


def test_digest_changes_with_handwritten_diff(repo):
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "tools/example.py", "# first\n")
    commit(repo)
    digest = diff_digest(repo, base, "HEAD")
    write(repo, "tools/example.py", "# second\n")
    commit(repo)
    assert diff_digest(repo, base, "HEAD") != digest

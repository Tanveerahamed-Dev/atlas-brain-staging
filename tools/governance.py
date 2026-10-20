"""Read-only AD-03/AD-07 guards and canonical review-diff hashing."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

MANIFEST = "governance/generators.json"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)


def blob(repo: Path, revision: str, path: str) -> bytes | None:
    for row in git(repo, "ls-tree", "-r", "-z", revision).split(b"\0"):
        if row:
            metadata, name = row.split(b"\t", 1)
            if name.decode("utf-8") == path:
                return git(repo, "cat-file", "blob", metadata.split()[2].decode("ascii"))
    return None


def resolve(repo: Path, revision: str) -> str:
    return git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").decode().strip()


def generated(repo: Path, base: str, head: str) -> tuple[str, ...]:
    before = json.loads(blob(repo, base, MANIFEST) or b"{}")
    after = json.loads(blob(repo, head, MANIFEST) or b"{}")
    if before != after:
        raise ValueError("AD-03: generator changes require a separate owner-approved registration")
    if not isinstance(before, dict) or any(
        not isinstance(path, str) or not re.fullmatch(r"[a-zA-Z0-9_.\-/]+", path, re.ASCII)
        or path.startswith("/") or ".." in path.split("/") for path in before
    ):
        raise ValueError("AD-03: invalid generator manifest")
    return tuple(sorted(before))


def excluded(path: str, outputs: tuple[str, ...]) -> bool:
    return path in outputs or path.startswith(("fixtures/", "tests/goldens/"))


def changes(repo: Path, base: str, head: str) -> list[tuple[bytes, bytes, str]]:
    rows = git(repo, "diff", "--numstat", "--no-renames", "-z", base, head).split(b"\0")
    return [(a, d, p.decode("utf-8")) for row in rows if row for a, d, p in [row.split(b"\t", 2)]]


def diff_digest(repo: Path, base: str, head: str) -> str:
    # Explicit formatting; never execute external diff drivers or text conversion helpers.
    base, head = resolve(repo, base), resolve(repo, head)
    outputs = generated(repo, base, head)
    paths = [p for _, _, p in changes(repo, base, head) if p not in outputs]
    patch = git(repo, "-c", "core.quotePath=true", "diff", "--binary", "--full-index",
                "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color",
                "--no-indent-heuristic", "--inter-hunk-context=0", "--no-relative",
                "--src-prefix=a/", "--dst-prefix=b/", "--unified=3", "--diff-algorithm=myers",
                base, head, "--", *[f":(literal){p}" for p in sorted(paths)]) if paths else b""
    return hashlib.sha256(patch).hexdigest()


def audit(repo: Path, base: str, head: str) -> dict[str, int | str]:
    base, head = resolve(repo, base), resolve(repo, head)
    outputs, count, classes = generated(repo, base, head), 0, set()
    for added, deleted, path in changes(repo, base, head):
        if not excluded(path, outputs):
            if b"-" in (added, deleted):
                raise ValueError("AD-03: uncountable binary change")
            count += int(added) + int(deleted)
            parts = path.split("/")
            if parts[0] == "atlas_brain" and len(parts) > 2:
                depth = 4 if parts[1] == "packs" else 3 if parts[1] == "platform" else 2
                classes.add("/".join(parts[:depth]))
        if path.startswith("docs/adr/"):
            old, new = blob(repo, base, path), blob(repo, head, path)
            text = new.decode("utf-8") if new is not None else ""
            if len(text.splitlines()) > 60 or len(text) > 4000:
                raise ValueError("AD-07: ADR exceeds 60 lines or 4000 characters")
            if old and re.search(rb"(?m)^Status: accepted\r?$", old, re.ASCII):
                def strip_status(data: bytes) -> bytes:
                    return re.sub(rb"(?m)^Status:[^\n]*(?:\n|$)", b"", data)
                if new is None or strip_status(old) != strip_status(new):
                    raise ValueError("AD-07: accepted ADR is immutable except its status line")
    if count > 400 or len(classes) > 1:
        raise ValueError("AD-03: more than 400 changed lines or multiple production path classes")
    return {"counted_lines": count, "diff_sha256": diff_digest(repo, base, head),
            "base_sha": base, "head_sha": head}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    try:
        print(json.dumps(audit(Path.cwd(), args.base, args.head), sort_keys=True))
        return 0
    except (ValueError, TypeError, OSError, subprocess.CalledProcessError):
        print("governance audit refused; inspect AD-03/AD-07 self-tests and input commits")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

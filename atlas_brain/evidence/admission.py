"""Version-one folder bundles: fail closed before exposing any capture."""
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath
import stat
from typing import cast


class AdmissionRefused(ValueError):
    """The entire bundle is inadmissible; the message is a stable receipt code."""


class BudgetExceeded(ValueError):
    reason = "budget_exceeded"

    def __init__(self, member: str):
        self.member = member
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True)
class Budgets:
    bundle_bytes: int
    artifact_bytes: int
    artifacts: int

    def __post_init__(self) -> None:
        if any(type(n) is not int or n <= 0 for n in asdict(self).values()):
            raise ValueError("invalid_budget")

    @property
    def sha256(self) -> str:
        return sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def member_names(names: list[str]) -> None:
    seen: dict[str, str] = {}
    for name in names:
        parts = name.split("/")
        if (not name or PurePosixPath(name).is_absolute() or "\\" in name or ":" in name
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or any(p in ("", ".", "..") for p in parts)):
            raise AdmissionRefused("unsafe_member_name")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            key = prefix.casefold()
            if key in seen and (seen[key] != prefix):
                raise AdmissionRefused("name_collision")
            seen[key] = prefix
    if len(names) != len(set(names)):
        raise AdmissionRefused("duplicate_member")


def strict_json(raw: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise AdmissionRefused("duplicate_json_key")
            result[key] = value
        return result

    def constant(_: str) -> object:
        raise AdmissionRefused("nonfinite_json")

    def number(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            raise AdmissionRefused("nonfinite_json")
        return value

    try:
        return cast(object, json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                                       parse_constant=constant, parse_float=number))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AdmissionRefused("invalid_json") from error


def record(value: object, fields: tuple[str, ...]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise AdmissionRefused("invalid_record_fields")
    return cast(dict[str, object], value)


def string(row: dict[str, object], field: str) -> str:
    value = row[field]
    if not isinstance(value, str):
        raise AdmissionRefused("invalid_string")
    return value


@dataclass(frozen=True, slots=True)
class Attempt:
    source: str
    operation: str
    attempted: str
    succeeded: str
    transport_defect: str

    def __post_init__(self) -> None:
        if self.attempted not in ("yes", "no", "unknown") or self.succeeded not in ("yes", "no", "unknown"):
            raise AdmissionRefused("invalid_attempt")
        if self.succeeded != "unknown" and self.attempted != "yes":
            raise AdmissionRefused("contradictory_attempt")

    @property
    def detail(self) -> str:
        return "attempt_unknown" if self.attempted == "unknown" else self.transport_defect


def folder_members(root: Path, budgets: Budgets) -> dict[str, bytes]:
    paths: list[Path] = []
    names: list[str] = []
    pending = [root]
    if root.is_symlink() or root.is_junction():
        raise AdmissionRefused("linked_root")
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir()):
            info = child.lstat()
            name = child.relative_to(root).as_posix()
            names.append(name)
            if child.is_symlink() or child.is_junction() or info.st_nlink > 1 and not stat.S_ISDIR(info.st_mode):
                raise AdmissionRefused("linked_member")
            if stat.S_ISDIR(info.st_mode):
                pending.append(child)
            elif stat.S_ISREG(info.st_mode):
                paths.append(child)
            else:
                raise AdmissionRefused("special_member")
    member_names(names)
    if len(paths) > budgets.artifacts:
        raise BudgetExceeded("bundle")
    if sum(path.stat().st_size for path in paths) > budgets.bundle_bytes:
        raise BudgetExceeded("bundle")
    result: dict[str, bytes] = {}
    for path in sorted(paths):
        name = path.relative_to(root).as_posix()
        with path.open("rb") as stream:
            raw = stream.read(budgets.artifact_bytes + 1)
        if len(raw) > budgets.artifact_bytes:
            raise BudgetExceeded(name)
        if name.endswith(".json"):
            strict_json(raw)
        result[name] = raw
    return result

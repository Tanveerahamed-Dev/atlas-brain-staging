"""Version-one folder bundles: fail closed before exposing any capture."""
import json
import math
import stat
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from atlas_brain.kernel import states as k
from atlas_brain.kernel.states import CaptureId
from atlas_brain.kernel.time import BoundSource, TimeInterval

from .capture import Capture, Channel, Scope, classify_cli, unrecorded_time
from .text import text_lines


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
    if not isinstance(value, dict):
        raise AdmissionRefused("invalid_record_fields")
    value = cast(dict[str, object], value)
    if set(value) != set(fields):
        raise AdmissionRefused("invalid_record_fields")
    return value


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
        if any(type(value) is not str or not value.strip() for value in (self.source, self.operation)):
            raise AdmissionRefused("invalid_operation_identity")
        if self.attempted not in ("yes", "no", "unknown") or self.succeeded not in ("yes", "no", "unknown"):
            raise AdmissionRefused("invalid_attempt")
        if self.succeeded != "unknown" and self.attempted != "yes":
            raise AdmissionRefused("contradictory_attempt")
        if self.succeeded == "yes" and self.transport_defect:
            raise AdmissionRefused("contradictory_transport_success")

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
        if name.casefold().endswith(".json"):
            strict_json(raw)
        result[name] = raw
    return result


@dataclass(frozen=True, slots=True)
class Bundle:
    id: str
    importer: str
    manifest_sha256: str
    options_sha256: str
    attempts: tuple[Attempt, ...]
    captures: tuple[Capture, ...]


def import_folder(root: Path, budgets: Budgets) -> Bundle:
    members = folder_members(root, budgets)
    if "manifest.json" not in members:
        raise AdmissionRefused("missing_manifest")
    manifest = record(strict_json(members["manifest.json"]), ("version", "bundle_id", "importer", "attempts", "captures"))
    if type(manifest["version"]) is not int or manifest["version"] not in (1, 2):
        raise AdmissionRefused("unsupported_manifest_version")
    attempts: list[Attempt] = []
    captures: list[Capture] = []
    for field in ("attempts", "captures"):
        if not isinstance(manifest[field], list):
            raise AdmissionRefused("invalid_manifest_list")
    for value in cast(list[object], manifest["attempts"]):
        row = record(value, ("source", "operation", "attempted", "succeeded", "transport_defect"))
        attempts.append(Attempt(*(string(row, f) for f in ("source", "operation", "attempted", "succeeded", "transport_defect"))))
    keys = [(a.source, a.operation) for a in attempts]
    if len(keys) != len(set(keys)):
        raise AdmissionRefused("duplicate_attempt")
    paths: list[str] = []
    capture_fields = ("path", "source", "operation", "rendered", "codec", "sha256", "prompt_verified")
    extra_fields = ("scope", "collected_utc") if manifest["version"] == 2 else ()
    for value in cast(list[object], manifest["captures"]):
        row = record(value, capture_fields + extra_fields)
        path, source, operation, rendered, codec, digest = (string(row, f) for f in ("path", "source", "operation", "rendered", "codec", "sha256"))
        member_names([path])
        if PurePosixPath(path).parts[:-1] != ("devices", source, "captures"):
            raise AdmissionRefused("capture_source_path_mismatch")
        paths.append(path)
        if path not in members or sha256(members[path]).hexdigest() != digest or path == "manifest.json":
            raise AdmissionRefused("capture_hash_mismatch")
        if type(row["prompt_verified"]) is not bool:
            raise AdmissionRefused("invalid_prompt_flag")
        attempt = next((a for a in attempts if (a.source, a.operation) == (source, operation)), Attempt(source, operation, "unknown", "unknown", ""))
        if (source, operation) not in keys:
            attempts.append(attempt)
            keys.append((source, operation))
        raw = members[path]
        try:
            lines = text_lines(raw, codec)
        except (ValueError, LookupError) as error:
            raise AdmissionRefused("unsupported_capture_codec") from error
        capture_id = capture_identity(row, attempt, raw)
        source_id = k.EntityKey("node:" + source)
        witness = k.EvidenceRef(capture=capture_id, locator=k.WholeCapture(), role=k.EvidenceRole.SUBJECT,
                                excerpt_sha256=sha256(raw).hexdigest())
        scope, collected = capture_metadata(row, source_id, witness, manifest["version"] == 2)
        captures.append(Capture(id=capture_id, source=source_id, channel=Channel.CLI, operation=operation,
                                rendered=rendered, scope=scope, collected_utc=collected,
                                codec=codec, raw=raw, integrity=classify_cli(raw, attempt.succeeded, row["prompt_verified"]),
                                error=None, integrity_evidence=(witness,), read_scope=k.ReadScope.UNKNOWN,
                                read_scope_evidence=(), view=k.ViewConsistency.UNKNOWN, envelope=None, lines=lines))
    member_names(paths)
    return Bundle(string(manifest, "bundle_id"), string(manifest, "importer"), sha256(members["manifest.json"]).hexdigest(),
                  budgets.sha256, tuple(attempts), tuple(captures))


def capture_identity(row: dict[str, object], attempt: Attempt, raw: bytes) -> CaptureId:
    metadata = {"capture": row, "attempt": asdict(attempt)}
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return CaptureId("cap:" + sha256(canonical + b"\0" + raw).hexdigest())


def capture_metadata(row: dict[str, object], source: k.EntityKey, witness: k.EvidenceRef,
                     version_two: bool) -> tuple[Scope, TimeInterval | k.Unknown]:
    fields = ("vrf", "context", "vdc", "tenant", "afi", "instance", "plane")
    scope = record(row["scope"], fields) if version_two else dict.fromkeys(fields)
    plane = scope["plane"] if version_two else "exec"
    if plane not in ("exec", "admin", "controller"):
        raise AdmissionRefused("invalid_plane")
    values: list[str | None] = []
    for field in fields[:-1]:
        value = scope[field]
        if value is not None and (not isinstance(value, str) or not value):
            raise AdmissionRefused("invalid_scope")
        values.append(value)
    result = Scope(node=source, vrf=values[0], context=values[1], vdc=values[2], tenant=values[3],
                   afi=values[4], instance=values[5], plane=cast(Literal["exec", "admin", "controller"], plane))
    if not version_two or row["collected_utc"] is None:
        return result, unrecorded_time(witness)
    time = record(row["collected_utc"], ("earliest", "latest", "clock", "bound"))
    if type(time["earliest"]) is not int or type(time["latest"]) is not int or time["bound"] != "collector_recorded":
        raise AdmissionRefused("invalid_collector_time")
    try:
        interval = TimeInterval(earliest=time["earliest"], latest=time["latest"], clock=string(time, "clock"),
                                bound=BoundSource.COLLECTOR_RECORDED)
        if not interval.clock.startswith("collector:"):
            raise ValueError("collector_clock_required")
    except ValueError as error:
        raise AdmissionRefused("invalid_collector_time") from error
    return result, interval

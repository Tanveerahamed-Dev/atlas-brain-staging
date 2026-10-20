"""ZIP32 payload admission: bounded reads, no extraction or nested archives."""
import stat
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile
from zlib import error as DecompressionError

from .admission import (
    AdmissionRefused,
    BudgetExceeded,
    Budgets,
    Bundle,
    import_members,
    member_names,
    strict_json,
)


def zip_members(path: Path, budgets: Budgets) -> dict[str, bytes]:
    info = path.lstat()
    if path.is_symlink() or path.is_junction() or info.st_nlink > 1 or not stat.S_ISREG(info.st_mode):
        raise AdmissionRefused("linked_or_special_archive")
    result: dict[str, bytes] = {}
    expanded = 0
    try:
        with path.open("rb") as source:
            # Closed initial profile: no ZIP64, spanning, archive comment or appended data.
            source.seek(0, 2)
            size = source.tell()
            source.seek(max(0, size - 22))
            end = source.read(22)
            if (len(end) != 22 or end[:4] != b"PK\x05\x06" or end[4:8] != b"\0" * 4
                    or end[8:10] != end[10:12] or end[20:22] != b"\0\0"):
                raise AdmissionRefused("unsupported_zip_profile")
            count = int.from_bytes(end[10:12], "little")
            index_size = int.from_bytes(end[12:16], "little")
            offset = int.from_bytes(end[16:20], "little")
            if count == 65535 or index_size == 0xffffffff or offset == 0xffffffff or offset + index_size != size - 22:
                raise AdmissionRefused("unsupported_zip_profile")
            if count > budgets.artifacts or index_size > budgets.archive_index_bytes:
                raise BudgetExceeded("bundle")
            # Verify actual index count/shape before ZipFile allocates its directory.
            source.seek(offset)
            actual = 0
            while source.tell() < offset + index_size:
                header = source.read(46)
                if len(header) != 46 or header[:4] != b"PK\x01\x02":
                    raise AdmissionRefused("invalid_zip_index")
                skip = sum(int.from_bytes(header[i:i + 2], "little") for i in (28, 30, 32))
                source.seek(skip, 1)
                actual += 1
                if actual > budgets.artifacts:
                    raise BudgetExceeded("bundle")
                if source.tell() > offset + index_size:
                    raise AdmissionRefused("invalid_zip_index")
            if actual != count:
                raise AdmissionRefused("invalid_zip_index")
            with ZipFile(source) as archive:
                entries = archive.infolist()
                names = [i.orig_filename[:-1] if i.is_dir() else i.orig_filename for i in entries]
                member_names(names)
                files = {i.filename for i in entries if not i.is_dir()}
                for name in names:
                    parts = name.split("/")
                    if len(parts) > budgets.nesting_depth:
                        raise BudgetExceeded(name)
                    if any("/".join(parts[:i]) in files for i in range(1, len(parts))):
                        raise AdmissionRefused("zip_path_conflict")
                for entry, name in zip(entries, names, strict=True):
                    mode = entry.external_attr >> 16
                    if entry.flag_bits & 1:
                        raise AdmissionRefused("encrypted_zip_member")
                    if entry.compress_type not in (ZIP_STORED, ZIP_DEFLATED):
                        raise AdmissionRefused("unsupported_zip_compression")
                    if entry.is_dir():
                        if entry.file_size or (stat.S_IFMT(mode) and not stat.S_ISDIR(mode)):
                            raise AdmissionRefused("special_zip_member")
                        continue
                    if stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                        raise AdmissionRefused("special_zip_member")
                    chunks: list[bytes] = []
                    member_size = 0
                    with archive.open(entry) as member:
                        while True:
                            chunk = member.read(min(65536, budgets.artifact_bytes - member_size + 1,
                                                    budgets.bundle_bytes - expanded + 1))
                            if not chunk:
                                break
                            member_size += len(chunk)
                            expanded += len(chunk)
                            if member_size > budgets.artifact_bytes or member_size > entry.compress_size * budgets.compression_ratio:
                                raise BudgetExceeded(name)
                            if expanded > budgets.bundle_bytes:
                                raise BudgetExceeded("bundle")
                            chunks.append(chunk)
                    raw = b"".join(chunks)
                    if (Path(name).suffix.casefold() in (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz")
                            or raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b"))
                            or raw[257:262] == b"ustar"):
                        raise AdmissionRefused("nested_archive")
                    if name.casefold().endswith(".json"):
                        strict_json(raw, budgets.nesting_depth, budgets.numeric_digits, name)
                    result[name] = raw
    except (AdmissionRefused, BudgetExceeded):
        raise
    except (BadZipFile, OSError, EOFError, RuntimeError, NotImplementedError, ValueError, DecompressionError) as error:
        raise AdmissionRefused("invalid_zip") from error
    return result


def import_zip(path: Path, budgets: Budgets) -> Bundle:
    return import_members(zip_members(path, budgets), budgets)

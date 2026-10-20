"""Planted hostile ZIP members and bounded streaming controls for M1."""
import stat
import zipfile
from unittest.mock import patch

import pytest
from test_evidence import bundle

from atlas_brain.evidence import admission as a
from atlas_brain.evidence import archives as z


def archive(tmp_path, rows, *, compression=zipfile.ZIP_STORED):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w", compression=compression) as stream:
        for name, raw in rows:
            stream.writestr(name, raw)
    return path


def limits(**changes):
    return a.Budgets(1000000, 500000, 100, **changes)


def test_streamed_zip_matches_folder_identity_and_never_extracts(tmp_path):
    root = tmp_path / "folder"
    root.mkdir()
    bundle(root, raw=b"record\n")
    path = archive(tmp_path, [(p.relative_to(root).as_posix(), p.read_bytes())
                              for p in sorted(root.rglob("*")) if p.is_file()])
    with (patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("extracted")),
          patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("extracted"))):
        assert z.import_zip(path, limits()) == a.import_folder(root, limits())
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.zip", "folder"]


@pytest.mark.parametrize("names", [["../escape"], ["/absolute"], ["D:escape"],
                                    ["a\\b"], ["a", "A"], ["a", "a"]])
def test_unsafe_and_duplicate_zip_names_refuse(tmp_path, names):
    path = archive(tmp_path, [(name, b"data") for name in names])
    with pytest.raises(a.AdmissionRefused):
        z.zip_members(path, limits())


@pytest.mark.parametrize("kind", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR])
def test_nonregular_unix_members_refuse(tmp_path, kind):
    info = zipfile.ZipInfo("member")
    info.create_system = 3
    info.external_attr = (kind | 0o600) << 16
    with pytest.raises(a.AdmissionRefused, match="special_zip_member"):
        z.zip_members(archive(tmp_path, [(info, b"target")]), limits())


@pytest.mark.parametrize("raw", [b"PK\x03\x04nested", b"PK\x05\x06nested", b"\x1f\x8bdata",
                                  b"\0" * 257 + b"ustar" + b"\0" * 300])
def test_nested_archives_refuse_by_bytes(tmp_path, raw):
    with pytest.raises(a.AdmissionRefused, match="nested_archive"):
        z.zip_members(archive(tmp_path, [("plain.txt", raw)]), limits())


def test_nested_archive_extension_refuses_even_without_magic(tmp_path):
    with pytest.raises(a.AdmissionRefused, match="nested_archive"):
        z.zip_members(archive(tmp_path, [("inner.TGZ", b"invalid archive")]), limits())


def test_ratio_budget_stops_during_bounded_reads(tmp_path):
    path = archive(tmp_path, [("bomb.txt", b"a" * 200000)], compression=zipfile.ZIP_DEFLATED)
    original = zipfile.ZipExtFile.read
    reads = []
    def observed(stream, size):
        reads.append(size)
        assert 0 < size <= 65536
        return original(stream, size)
    with (patch.object(zipfile.ZipExtFile, "read", observed), pytest.raises(a.BudgetExceeded) as refused):
        z.zip_members(path, limits(compression_ratio=1))
    assert refused.value.member == "bomb.txt"
    assert len(reads) == 1


@pytest.mark.parametrize("which", ["artifact", "bundle", "count", "index", "depth"])
def test_hashed_archive_budgets_refuse(tmp_path, which):
    path = archive(tmp_path, [("a/b.txt", b"1234"), ("other.txt", b"1234")])
    budgets = {"artifact": a.Budgets(1000, 3, 10), "bundle": a.Budgets(7, 1000, 10),
               "count": a.Budgets(1000, 1000, 1), "index": limits(archive_index_bytes=1),
               "depth": limits(nesting_depth=1)}[which]
    with pytest.raises(a.BudgetExceeded):
        z.zip_members(path, budgets)


def test_declared_entry_count_is_checked_before_zipfile_allocation(tmp_path):
    path = archive(tmp_path, [("a", b"a"), ("b", b"b")])
    with (patch.object(z, "ZipFile", side_effect=AssertionError("index allocated")),
          pytest.raises(a.BudgetExceeded)):
        z.zip_members(path, a.Budgets(1000, 1000, 1))


def test_crc_corruption_refuses_and_returns_no_members(tmp_path):
    path = archive(tmp_path, [("a", b"payload")])
    path.write_bytes(path.read_bytes().replace(b"payload", b"payloae", 1))
    with pytest.raises(a.AdmissionRefused, match="invalid_zip"):
        z.zip_members(path, limits())


@pytest.mark.parametrize("raw", [b"not a zip", b"PK\x03\x04"])
def test_invalid_archive_refuses(tmp_path, raw):
    path = tmp_path / "bad.zip"
    path.write_bytes(raw)
    with pytest.raises(a.AdmissionRefused):
        z.zip_members(path, limits())


def test_index_mismatch_and_unsupported_comment_refuse(tmp_path):
    path = archive(tmp_path, [("a", b"x")])
    raw = bytearray(path.read_bytes())
    raw[-12:-10] = (2).to_bytes(2, "little")
    path.write_bytes(raw)
    with pytest.raises(a.AdmissionRefused):
        z.zip_members(path, limits())
    path = archive(tmp_path, [("a", b"x")])
    with zipfile.ZipFile(path, "a") as stream:
        stream.comment = b"comment"
    with pytest.raises(a.AdmissionRefused):
        z.zip_members(path, limits())


def test_json_and_path_tree_refusals_apply_inside_zip(tmp_path):
    for rows in ([('a.JSON', b'{"x":1,"x":2}')], [("a", b"x"), ("a/b", b"x")]):
        with pytest.raises(a.AdmissionRefused):
            z.zip_members(archive(tmp_path, rows), limits())


@pytest.mark.parametrize("field", ["compression_ratio", "archive_index_bytes"])
def test_archive_options_are_positive_integers_and_hashed(field):
    assert limits().sha256 != limits(**{field: 5}).sha256
    for bad in (0, -1, True):
        with pytest.raises(ValueError):
            limits(**{field: bad})

# Public fixture provenance, M0

Run `python tools/provenance.py` from the repository root. No runtime dependency
is needed. An absent default `fixtures/` is allowed before corpus import; an
explicit missing root is refused. Each fixture directory contains exactly one
raw file and `provenance.yaml`; every other file needs its own record/directory.
Links, duplicate fixture IDs, orphan records and unrecorded files are refused.
Git attributes keep fixture bytes unchanged; hashes include original line endings.

The exact YAML subset is UTF-8, LF or CRLF, blank lines, two-space-indented block mappings,
lowercase snake_case keys, and string scalars only. Strings are JSON double-quoted
strings or bare ASCII tokens matching `[A-Za-z][A-Za-z0-9_.-]*`. No comments,
single quotes, flow collections, lists, tags, anchors, aliases, nulls, booleans,
document markers, duplicate/unknown keys or implicit numeric scalars are accepted.
All fields below are required. `file` names one sibling raw file. Repository
commits are full lowercase 40/64-character hashes; paths are relative POSIX paths.

```yaml
fixture_id: example-version
file: output.txt
tier: P
source:
  kind: library_testdata
  repository:
    url: "https://github.com/example/corpus"
    commit: "<full source commit hash>"
    path: "samples/output.txt"
platform:
  family: iosxe
  model: C8000V
  version: "17.1"
  version_basis: source_stated
licence:
  name: "<source licence name>"
  redistribution: public
  notice: "<full required notice text, or explicit no-notice statement>"
sha256: "<SHA-256 of raw output.txt bytes>"
```

The public M0 subset accepts P/library_testdata and S/synthetic. H and L belong
in the private truth repository. M is refused until parent/mutation/token-witness
validation exists. Excluded sources are never accepted. Other S6 record extensions
(capture, privacy, truth) require an explicit schema extension before import.
Unknown platform/version uses `unstated` for all three and `version_basis: unknown`;
this can test robustness, never a train's format floor. S may also use `observed`.
P requires `source_stated` for a stated platform/version; P never proves accuracy.
This gate checks declared provenance and byte integrity, not upstream authenticity,
licence correctness, privacy clearance or parser-census qualification.

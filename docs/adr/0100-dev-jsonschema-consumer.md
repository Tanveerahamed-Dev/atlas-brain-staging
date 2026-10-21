# ADR-0100: development-only JSON Schema consumer

Status: proposed

## Decision candidate
Pin jsonschema==4.26.0 in the hashed dev lock only, with no optional format extras.
Use Draft202012Validator to check generated schemas and actual contract wire bytes.
S3 section3.5 requires a development-only result validator; S2 DA-4/DA-7 govern admission.
The runtime dependency list stays empty; atlas_brain cannot import this test library.
The consumer refuses external schema references/IDs, noncanonical bytes, floats and
unsafe integers; empty JSONL does not bypass schema validation or imply health.

## DA-7 evidence and boundaries (checked 2026-10-21)
(a) Not a parser, fact producer or runtime engine component; parser admission is N/A.
(b) Runtime admission is N/A; native Linux/Windows consumer tests are required anyway.
(c) Licence: MIT; redistribution is permitted with copyright/permission notice kept.
Nothing from this dev closure is shipped; preserve the MIT notice if that ever changes.
Pinned licence: https://github.com/python-jsonschema/jsonschema/blob/a7277432b0f7bcd0551f6e589d30457017125df4/COPYING
PyPI metadata: https://pypi.org/pypi/jsonschema/4.26.0/json
Core closure is attrs, jsonschema-specifications, referencing and rpds-py; their
current PyPI metadata reports MIT. Exact versions/hashes must be the hosted uv.lock.
(d) CT proposes; an independent REV2 DA-7 admission decision is required before adoption.
(e) PyPI JSON reports4.26.0 first uploaded2026-01-07T13:41:05Z, one release in the
2025-10-21 through2026-10-21 window, and Python>=3.10 including the3.14 classifier.
PyPI maintenance source: https://pypi.org/pypi/jsonschema/json
GitHub's release page agrees on v4.26.0 and displays179 commits to main since it:
https://github.com/python-jsonschema/jsonschema/releases/tag/v4.26.0
Anonymous REST metadata was rate-limited; archive/latest-default-commit REST fields
remain UNVERIFIED. This gap is not silently converted to a maintenance attestation;
the independent admission decision must explicitly resolve the DA-7 evidence boundary.
REST sources: https://api.github.com/repos/python-jsonschema/jsonschema
https://api.github.com/repos/python-jsonschema/jsonschema/releases/latest
https://api.github.com/repos/python-jsonschema/jsonschema/commits?per_page=1

## Validation and disposition
Metaschema, actual header/evidence instances, malformed data, offline references,
JSONL framing and real CLI success/refusal must pass on both hosted OS jobs.
No local installation/runtime acceptance. This remains a proposal until independently
approved; green tests alone neither adopt the library nor complete contract v0.

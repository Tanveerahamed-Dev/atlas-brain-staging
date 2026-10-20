# Declared raw-output mutations

`tools/mutations.py` is a standard-library truth-harness utility. `OPERATORS` is
immutable: each declaration exposes its complete byte-token set and permitted
bidirectional transitions. Numeric sets are generated, never arbitrary strings.

| Operator | Declared vocabulary | Engine v1 use |
|---|---|---|
| ospf-state | FULL ↔ EXSTART, EXCHANGE, INIT, 2WAY | U2a/U2b; U3 operand |
| duplex | full/half, a-full/a-half, Full-duplex/Half-duplex | L1-02/L1-10; preserves auto prefix |
| psu-state | OK/Ok ↔ Absent; OK ↔ Not Present/failed; active ↔ bad-input | L1-05 logic only |
| native-vlan | decimal 1–4094 | U4a/U4b one-end operand |
| err-disabled | connected ↔ err-disabled | L1-01 |
| admin-up-oper-down | is up, line protocol is up/down; is up/down | L1-01; select oper header, preserve admin line |
| mtu | decimal 68–65535 | U1a; U3 operand; no header conversion |
| duplicate-address | hosts 1–254 in the three documentation IPv4 /24s | C-19 swap operand |

`apply_span(raw, operator, start, end, after)` changes exactly one caller-selected
field at the half-open **byte** span `[start,end)`. It refuses absent, partial,
undeclared and no-op tokens; it never searches for a fallback occurrence. All bytes
outside the span survive, including UTF-8 prefixes, CRLF and missing final newlines.
It is a bare text transform and supplies no tier or device-semantic claim.

`mutate(parent, operator, start, end, after, witness, witness_start, witness_end)`
also checks both raw digests, H/L/P tiers, a known identical family/exact train,
and the verbatim complete replacement at the witness span. `Capture` is a small
trusted-loader projection, not a provenance schema or attestation oracle. Validate
source metadata through the shared provenance gate before projecting it; do not
infer a train from an unversioned sample or bypass a source-version conflict.
The result is bytes plus a deterministic M derivation receipt containing parent
ID/hash/provenance, operator, edit bytes/offsets, witness ID/hash/provenance/span,
output hash and content-derived mutation ID. It is not a signed truth-case record.

The caller owns field selection, applicable platform grammar, peer/domain/bay
identity and independently registered fault/healthy/insufficient labels. A VLAN
edit on a non-trunk is not a mismatch; a duplicated address needs a closed common
domain; EXSTART plus MTU edits do not prove causation. Compose U3 from separately
witnessed MTU and OSPF derivations. I1–I10 bundle operators are a separate harness
contract; tier-P edits cannot satisfy the H/L insufficient-evidence holdout quota.

Pinned Q inputs are copied byte-for-byte from `q/public-corpus` commit
`ef92126e9f2ae2161c02f050f4fba29932dc117e` into `fixtures/mutations/q/`, preserving
notices/licences and original sidecars renamed `source-provenance.yaml`. Sidecars
are historical source records; shared-schema acceptance is not verified. Current
Q parents lack eligible same-train fault-token witnesses. Tests must refuse M,
while explicitly synthetic loader doubles exercise the positive path. No generated
M fixture, format-floor, measured accuracy or verified-device claim is supplied.
Hosted Linux and Windows tests check planted refusals, inverse controls, exact
byte preservation and identical receipts across two fresh hash-seeded processes.

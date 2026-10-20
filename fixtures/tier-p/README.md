# Tier-P public corpus

This is format and robustness evidence, never device-semantic or accuracy truth.
The census covers the 54 Engine v1 variants (28 IOS-XE, 26 NX-OS).

- Public exact-family/form candidates: 44; source-stated versions: 8.
- No exact public source found in the searched corpora: 10.
- Imported variants: 18; unconflicted version-stated format floors: 1.
- Shortlisted inventory candidates: 93. All four repositories were checked for every variant.

The census distinguishes discovery coverage from imported coverage. A candidate with
identifiers is reference-only: raw data was neither redacted nor copied into this corpus.
Generic IOS driver labels do not establish IOS-XE. Similar commands, per-interface
captures, JSON variants, filtered output and default-VRF samples do not establish
coverage of a different command. The NX-OS role form uses the provisional spelling
show role; the adapter author still owns its read-scope suitability and spelling.

inventory.csv records each shortlisted candidate's immutable URL, commit, source path,
licence, source-stated platform/version, raw SHA-256, line/byte counts, lexical fault
witness locations, disposition and imported destination. census.csv records all 54
variants against all four repositories. sources.json pins the source archives and
licence hashes. _licences preserves upstream notices. Full Apache text accompanies
NTC's shorter upstream attribution notice.

Source capture time, tool, privilege and collection-attempt status are unstated;
null values preserve that uncertainty. An import success is not a device-capture
success. The provenance validator has not landed; schema acceptance is not verified.
The privacy result records the Q import screen and review of selected bytes, not a
promotion-gate receipt, owner-marker scan or supervisor approval. Scanner scope:
non-documentation IPv4; IPv6-shaped tokens; MACs including short hex octets; serial
patterns; prompts/hostnames; domains; credentials; descriptions and custom VRF names.
No exemptions or changed raw bytes were used. Public provenance cannot establish
that a library sample was originally captured without editing.

Unknown-version fixtures cannot satisfy C-39. The unconflicted imported floor is
NX-OS 6.2(14) 7009 show interface status. It uses the explicit 7009_6_2_14 source
label, corroborated by its sibling version banner. IOS-XE C9300 show vrf detail is
held: its 16.10.1 path label conflicts with the sibling version file's development
build BLD_V1610_THROTTLE_LATEST_20180903_070602_V16_10_0_101_2. No exact release
claim is made for that held candidate pending source clarification.
Other NAPALM version labels retain their literal underscore notation in the inventory;
no compatibility range is inferred from their spelling. Fault-token matches are
lexical witnesses, sometimes in legends, not manifested faults. No imported files
establish a two-device native-VLAN difference. Same-family/train token witnesses and
independent pre-registered labels are required before tier-M logic measurements.

No upstream expected-output files were read, imported or executed. No truth labels,
mutations, holdout records, parser support claims or measured metrics are supplied.
No CI acceptance is claimed: this branch intentionally has no PR pending the M0
provenance validator. The supervisor must review and run exact-head CI later.
# ADR-0006: ADR-0002 amendment for K token scope

Status: accepted

Supersedes ADR-0005; all previous global and per-file grants remain unchanged.
Standing supervisor approval:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
Exact using-path request:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/66#issuecomment-6298784558
T = atlas_brain/kernel/token_lints.py, actual source
066b1ed8a767b1a3edd8b399e82afe264d33b3af (22 AST endpoints).

| Additional API | Using path | Reason |
|---|---|---|
| ast.AnnAssign | T | Detect annotated value branches. |
| ast.Assign | T | Detect assignment value branches. |
| ast.Compare | T | Recognize literal enum comparisons. |
| ast.Constant | T | Identify literal keys and enum values. |
| ast.Expr | T | Recognize a sole assertion expression. |
| ast.MatchAs | T | Identify captured/default match arms. |
| ast.Return | T | Detect return value branches. |
| ast.stmt | T | Type statement sequences. |
| ast.Subscript | T | Recognize explicit mapping reads. |

This adds only nine bindings at T. No global AST or runtime grant is added.
The K full-lint grant and all PK grants remain unchanged. Hosted inventory
parses actual source without executing it; unlisted, outside-file, runtime
borrowing and re-export refusals remain mandatory. Admission does not certify
the K guard, audit repair, verdict logic or kernel freeze.
Future changes require a C1 amendment, independent MERGE-READY, supervisor
approval explicitly or within standing bounds, and green Linux/Windows CI.

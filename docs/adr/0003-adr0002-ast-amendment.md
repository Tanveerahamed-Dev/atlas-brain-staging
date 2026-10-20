# ADR-0003: ADR-0002 amendment for AST lint admission

Status: accepted

Supervisor approval under owner delegation, 2026-10-20:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/65#issuecomment-6296630147
This supersedes ADR-0002 while retaining its 22 global APIs and review conditions.
T = atlas_brain/kernel/token_lints.py; L = atlas_brain/kernel/lints.py.
Only the exact using paths below receive AST APIs; runtime paths receive none.
Types inspect parsed syntax; parse builds ASTs, walk/iter_child_nodes traverse them.

| API | Using paths |
|---|---|
| ast.AnnAssign | L |
| ast.arg | L |
| ast.Assign | L |
| ast.AST | T, L |
| ast.AsyncFor | L |
| ast.AsyncFunctionDef | L |
| ast.Attribute | T, L |
| ast.BinOp | L |
| ast.BitOr | L |
| ast.Call | T, L |
| ast.ClassDef | L |
| ast.comprehension | L |
| ast.Constant | L |
| ast.ExceptHandler | L |
| ast.expr | L |
| ast.For | L |
| ast.FunctionDef | L |
| ast.If | T |
| ast.IfExp | T |
| ast.Import | L |
| ast.ImportFrom | L |
| ast.iter_child_nodes | L |
| ast.Lambda | L |
| ast.Load | L |
| ast.Match | T |
| ast.MatchClass | T |
| ast.MatchOr | T |
| ast.MatchSingleton | T |
| ast.MatchValue | T |
| ast.Module | L |
| ast.Name | T, L |
| ast.NamedExpr | L |
| ast.parse | L |
| ast.pattern | T |
| ast.Set | L |
| ast.SetComp | L |
| ast.stmt | L |
| ast.Store | L |
| ast.Subscript | L |
| ast.walk | T, L |

No wildcard, compilation, execution, reflection or process grant is added.
Caller-path checks also apply to internal re-exports. The pinned request inventory
is checked in hosted CI; it does not certify K whole-source or lint acceptance.
Future API or path-grant changes require an amendment, REV MERGE-READY and explicit
supervisor approval. Implementation acceptance requires a green published exact
head on Linux and Windows and independent REV review. This is source policy only.

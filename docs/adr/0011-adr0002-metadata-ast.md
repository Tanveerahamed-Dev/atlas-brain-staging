# ADR-0011: ADR-0002 amendment for metadata grammar syntax inspection

Status: proposed

Extends ADR-0010; all prior global, runtime and per-file grants are unchanged.
Standing public-AST delegation, owner decision 2026-10-20 20:45:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
T = atlas_brain/kernel/metadata_readonly.py, published source
fe80965472ab447f789b60522f79603adc5a876d, blob 4b9fa0eb989dd47bd1f4a68a9e7dd4c1342cbcbf.
SHA-256: 8cde05ea2897a8e68d41ec5157e3ba7f247f3a86d176a50cda50fc7c32a0135a.
The hosted inventory parses this file as data and checks its actual tracked
source admission. It never imports or executes the component.

| Additional API | Using path | Syntax inspection purpose |
|---|---|---|
| ast.AST | T | Annotate parsed nodes. |
| ast.AnnAssign | T | Inspect local binding and annotation syntax. |
| ast.Assign | T | Inspect local binding syntax. |
| ast.AsyncFunctionDef | T | Identify an excluded function form. |
| ast.AsyncWith | T | Identify an excluded context form. |
| ast.Attribute | T | Inspect attribute access and call syntax. |
| ast.Call | T | Inspect call syntax. |
| ast.ClassDef | T | Identify an excluded class form. |
| ast.Dict | T | Identify collection syntax. |
| ast.DictComp | T | Identify collection syntax. |
| ast.ExceptHandler | T | Inspect exception binding syntax. |
| ast.FunctionDef | T | Inspect lexical function syntax. |
| ast.Global | T | Identify an excluded binding form. |
| ast.Import | T | Identify an excluded import form. |
| ast.ImportFrom | T | Identify an excluded import form. |
| ast.Lambda | T | Identify an excluded function form. |
| ast.List | T | Identify collection syntax. |
| ast.ListComp | T | Identify collection syntax. |
| ast.Load | T | Inspect access context syntax. |
| ast.Match | T | Identify an excluded matching form. |
| ast.Name | T | Inspect name syntax. |
| ast.Nonlocal | T | Identify an excluded binding form. |
| ast.Return | T | Inspect result syntax. |
| ast.Set | T | Identify collection syntax. |
| ast.SetComp | T | Identify collection syntax. |
| ast.Subscript | T | Inspect indexed access syntax. |
| ast.With | T | Identify an excluded context form. |
| ast.Yield | T | Identify an excluded generator form. |
| ast.YieldFrom | T | Identify an excluded generator form. |
| ast.iter_child_nodes | T | Traverse parsed children. |
| ast.walk | T | Traverse parsed annotations and type operands. |

Exactly these 31 endpoints bind only to T. Strings describing other APIs
are data, not grants. Unlisted APIs, wrong-file uses and runtime import hops
through T remain refused. No source/function/hash waiver is added.
Admission does not prove the protected-root/no-mutation/no-escape theorem,
lint-only output confinement, R3 observations or K implementation correctness.
Independent REV MERGE-READY and exact-head Linux/Windows gates remain required.
Historical native-receipt gaps, timing budgets and integration holds remain.

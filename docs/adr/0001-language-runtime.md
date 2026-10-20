# ADR-0001: runtime spike evidence (draft)

Status: provisional. S0-b, independent review and product-lock reconciliation remain open.
This is not a language acceptance or a merge approval.
The disposable `spike/` pipeline never merges. Plan item 5 is not open.

## Worker recycling: owner clarification, 2026-10-20

S3 section 3.4.1, line 222 measures **post-task resident accumulation** against
the first-task plateau. Per-task transient RSS peaks are recorded separately
and remain subject to the independent S0-a 2 GiB process-tree cap. They do not
by themselves justify recycling. The owner selected `max_tasks_per_child=None`.

The initial four-lane, 75-task-per-worker diagnostic used three external 20 Hz
quiet samples after each task, with no forced GC or allocator trimming. These
are measured maxima, not a population bound:

| OS | First-task RSS (bytes) | Maximum post-task RSS (bytes) | Post-task growth | Maximum transient growth |
| --- | ---: | ---: | ---: | ---: |
| Linux | 26,742,784 | 33,144,832 | 23.939347526420585% | 31.658753254709754% |
| Windows | 25,714,688 | 29,503,488 | 14.73399171710736% | 39.82159923542529% |

Recycling at 3 still had transient growth of 28.83814226199661% on Linux and
34.888148500713945% on Windows. Its post-task maxima were 14.781669495448232%
and 11.604423785863119%, respectively. This supports separating temporary task
allocations from accumulation; it does not prove absence of all future growth.

Source: [run 39442628198](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/actions/runs/39442628198),
head `1a763dda03193574f8a97cb10657b91428a10720`, 4 observed CPUs on both OSes.
Linux RAM was 16,766,414,848 bytes; Windows RAM was 17,174,360,064 bytes.
The retained raw index has SHA-256
`a0080707ca69d1cb543cd982fcb9c8bbfba2f35c7d0565a5b68c187cf44da8d9`:
4,322 retrieved files and 4,910 embedded raw digests verified. The workflow was
red under the earlier transient-peak interpretation; that negative evidence is
retained, not relabelled as a historically green run.

**Thin margin:** the initial Linux post-task result left only 1.06 percentage
points below 25%. The scale ratchet must remeasure post-task growth with real
packs in M1. The separately measured S0-a cap passed in the day-5 checkpoint.

**Later counterexample retained:** the diagnostic originally omitted the
normal metrics initializer. After matching it, [run 39443425120](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/actions/runs/39443425120),
head `0bb9b1b05bbff458215895547e219fc28f8586c6`, recorded Linux post-task RSS
26,877,952 -> 33,906,688 bytes, or 26.150563852484%. That exceeds 25% even under
the clarified rule. `None` was not qualified on that head and remained the
owner's selected default pending the bounded profile below.
That run also exposed three Windows PID reuses among 100 worker generations;
the probe now binds samples and acknowledgements to process birth identity.
Missing generations were refused, never counted as a passing growth result.

**Bounded profiling result:** the final birth-bound probe reproduced Linux
26.121331914246615% post-task growth in run 39445809827 at head
`e9f107fe700d7f2edf08c2e093690eefc896636c`. The task writer kept complete fact
rows, a whole JSON string and its encoded bytes together. One bounded profile
changed it to stream canonical JSON into the unpublished node file; no forced
collection or artificially inflated first-task baseline was added.

[Run 39446618389](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/actions/runs/39446618389),
head `59548d5d680ca3f7e2cbff3f72f2c554f3a64553`, passed both growth jobs:
post-task maxima with `None` were **22.716736207695873% Linux** and
**17.096165933375235% Windows**. Transient maxima remained 30.50533147890589%
and 35.75786015954951%, respectively. Recycling at 3 had post-task maxima
15.826006478482185% and 14.95518163233213%. Every diagnostic device file matched
its normal-run counterpart; the 300-device manifest also matched the prior
`c812629ee58d533293ca28ca09c62e5e04e5379bf2693910c0df50b9fc2de259`.
`max_tasks_per_child=None` therefore remains selected under the clarified rule.
The subsequent full performance, determinism and failure matrix qualifies the
new writer below. The M1 growth ratchet remains required.

## Guarded runtime qualification after the bounded profile

[Run 39447420195](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/actions/runs/39447420195)
at `2773cfd4fdde0b800662c23dc8f72f947f2107b5` passed all **22 executed jobs**.
The inactive product-install job was skipped and is not counted as green.
All figures below are hosted observations on that exact source; no local run
qualifies the engine. The runtime files remain byte-identical in the subsequent
installation-only head `bf5e58ea7667c0f32dcf8db49239d1c862377502`.

Both runners reported 4 CPUs. Linux RAM was 16,759,308,288 bytes and Windows RAM
17,174,360,064 bytes. These are the actual runner observations, not scaled
projections. Each run's OS image, interpreter, CPU and memory are in its receipt.

| OS | Devices | Five wall times (s) | Median (s) | Maximum (s) | Peak sampled tree USS (MiB) | Peak cap accounting (MiB) |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Linux | 100 | 3.552, 3.500, 3.571, 3.549, 3.551 | 3.551 | 3.571 | 152.53 | 173.85 |
| Linux | 300 | 7.701, 7.549, 7.655, 7.504, 7.499 | 7.549 | 7.701 | 178.40 | 240.07 |
| Linux | 1,000 | 21.729, 21.350, 21.597, 21.501, 21.551 | 21.551 | 21.729 | 265.02 | 467.12 |
| Windows | 100 | 3.352, 3.402, 3.402, 3.402, 3.352 | 3.402 | 3.402 | 113.13 | 126.45 |
| Windows | 300 | 8.902, 9.002, 9.002, 9.052, 9.002 | 9.002 | 9.052 | 138.48 | 152.62 |
| Windows | 1,000 | 28.553, 29.302, 28.352, 28.702, 30.252 | 28.702 | 30.252 | 227.70 | 241.48 |

All primary runs stayed under the hard 2 GiB cap. Linux cap accounting is final
cgroup memory including its supervisor and file cache; Windows is peak Job
committed memory. USS is the sampled comparable measure. Every stage stayed
inside its original budget. Non-exempt scaling exponents were Linux device
0.9127397682157332, Windows intake 0.9889707300326157 and Windows device
0.976828718820802. Other stages were below the 2-second exemption.

Dense 4 GiB-cap runs completed in 31.14994123300005 s Linux and
46.702053399999954 s Windows, each writing 367,154,588 result bytes. Peak USS
was 287,821,824 and 250,183,680 bytes; cap peaks were 647,938,048 cgroup bytes
and 264,212,480 Job bytes, respectively. Queue dumps/loads accounted for
3.920831681061768% to 6.687511060079827% of full-run device wall time; spawn
bootstrap serialization is excluded from that metric.

All 24 isolated acceptance rows and 8 separate fixed-seed probes matched.
All ten primary full-volume manifests remained
`65e14ee8f716b3195f8a1d0c185f074bed4bf8ca4015190a54cf1784511f7ddf`.
The 300-device cross-axis manifest remained
`c812629ee58d533293ca28ca09c62e5e04e5379bf2693910c0df50b9fc2de259`.
The four wrong-hash manual probes were refused as expected.

Twenty consecutive runs per OS and recycling mode completed. Population wall
CV was Linux None 6.30127349573255%, Linux 3 0.9693477038703392%, Windows None
5.305373082337194%, Windows 3 3.916052564781566%. Fault receipts prove single
retry equality, double-kill/cancel/MemoryError refusal, deterministic node-only
pack failure and preservation of the actual 302-file previous result.

Current-head post-task RSS maxima with None were **22.515025427646787% Linux**
and **18.251726302573758% Windows**. Transients were 30.389890584065343% and
36.707470182046453%. Recycling-at-3 post-task maxima were 16.02634467618002%
and 16.084573218480813%. Both None cells pass the clarified 25% accumulation
rule. The initial thin-margin warning and M1 remeasurement obligation remain.

Four startup cells each passed the five hook classes at prestart, coordinator
and worker entry, plus normal and broadly swallowed unlisted-import cases:
**68 refusals**, with no result publication. The prestart census executed no
hook. Host startup code may run before runtime refusal; that is detected,
not prevented. Clean `-S` output matched the ordinary isolated profile.
All 185 successful engine receipts enforced startup baselines. The independent
raw audit checked 30,752 recorded parent/worker import-set entries: zero resolved
modules outside the origin/hash-bound closure. Missing optional modules raise
`ModuleNotFoundError` without invoking a later finder; installed unlisted code
is denied before execution and a swallowed denial still refuses the run.
The Linux full-volume confined/host equality and positive network witness pass;
this does not claim Windows OS-level network isolation.

The retained raw index covers **13,078 files**, with **20,960 embedded digests
verified**, SHA-256
`f518ff11a9e38c3990ff3aacb25bec0796270a82a683e6a948ad3dfb0cb70e06`.
The complete machine report retains unrounded repetitions, stage maxima, GC,
payloads, worker-start timings, shapes and every raw-file digest. It is staged
for the final PR-5 evidence extraction; this draft is not that accepted PR.

## Complete planned native development closure

The declared product lock at `a02c5c52a118ee2b55ed770c830c1f2d0fade6b0` passed
runtime/development installation in run 39442628198, but omits S3's coverage
and Linux-only mutmut. That product declaration must be reconciled by its owner.
Main was rechecked at `a9a5a7baf2b63a92dbc13525fb45222eb0ac27a2`; its declared
development set still has the same omission.

A separate frozen S0 qualification lock includes every selected S3 tool:
`tools/scale/locked-plan/uv.lock`, SHA-256
`f4ab294aad75ad50614f4dbf74cc820a667f2840d588a8e1dae246d47f0924b0`.
It was generated only in hosted run 39448712055 using uv 0.13.1.
[Run 39449806169](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/actions/runs/39449806169)
at `bf5e58ea7667c0f32dcf8db49239d1c862377502` passed both smoke jobs and all
four native installation cells: Linux/Windows x Python 3.14.8/3.15.0.
No inactive job is counted as green. All installs used `uv sync --locked`.

Runtime profiles contained zero third-party distributions and zero startup
hooks. Full development profiles installed 26 distributions on Linux and 19
on Windows. Mutmut 3.8.0 is Linux-only; coverage 7.16.2 is present on both.
The native coverage tracer and the selected development imports worked under
the optional `-S` profile with purelib/platlib appended directly, without
`site.addsitedir`. Both projects are virtual in their locks, so there is no
editable-install file to report.

Each development environment had one executable `a1_coverage.pth`, separately
allowlisted by locked owner and wheel RECORD hash before normal startup:
Linux `ef2ed06d19867ec669c09a804060666a9cd5e383af0a9d11aa2de79b77d448e8`;
Windows `f1498191b7f52180654ccdb6195233612805e26344100c093058343ea04afd36`.
Their LF/CRLF forms differ. Both clean coordinator/worker module baselines were
recorded twice for normal and no-site profiles. Eight additional planted
unowned/tampered os-only hooks were refused before execution; positive controls
proved the hooks execute without the census, and the owned files were restored.

The installation raw index covers 84 files, SHA-256
`5a78892a0380c99ed478be324b1179890ac2b24f2ab7f87abd6298a60b4c3b33`.
This qualifies the full selected tool-set compatibility; it does not change
the product dependency declaration or accept future dependency changes.

## Other retained plan corrections and evidence boundaries

- `-I` ignores `PYTHONHASHSEED`. All isolated acceptance rows stay intact.
  Seeds 0 and 4242 are separate `-P -s -B` probes with a scrubbed environment,
  asserted flags and independent hash witnesses. They have separate clean
  startup baselines and are labelled equivalent manual isolation, not `-I`.
- The owner authorized a push trigger on `s0/spike`, with workflow/harness path
  filters and measurement commit markers; `workflow_dispatch` remains present.
- The public repository uses observed 4-CPU hosted runners. No 2-to-4-CPU
  extrapolation is used. Every measurement records actual CPUs and memory.
- Earlier cross-job Windows scaling exponents 1.6296568212284235 and
  1.5795711785370892 remain negative evidence in run 39429771512. Controlled
  same-runner measurements passed without loosening the 1.3 exponent threshold.
- The complete day-5 checkpoint is run 39433983328 at head
  `91cec70996aa9d68105b2085bc91285a6135a6c1`: all 16 jobs succeeded. Its 8,352-file
  raw index SHA-256 is
  `b246ec19c768a1686fce28fbf7c173ac2d257a249edc0e8b3c2f691d17464cdc`.
  Admission changes require new exact-head qualification; old results remain
  bound to their original source.
- K has not frozen the complete types, lint and verdict surface. SB's seeds
  remain independently owned and unscored. No S0-b catch count is inferred.

The final PR-5 version must include the complete S0 numbers and retained raw
digest indexes, plus independent review. This draft intentionally records no
complete language verdict while those gates remain open.

Model provenance follows the supervisor's app-selector attestation: author
`gpt-6.1-sol`, High; assigned reviewer REV2 `gpt-6-sol`, Extra High;
`attestation_source: supervisor (app model selector)`. Both are OpenAI; the
review is under the owner's same-family deviation, not cross-family review.
SB is assigned `gpt-6-astra`, also OpenAI, and its eventual calibration must
report that real provenance. Session metadata does not independently expose
these selections. No independent review or S0-b score is claimed here.

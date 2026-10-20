# ADR-0001: runtime spike evidence (draft)

Status: provisional. S0-b and final performance requalification remain open.
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
the clarified rule. The final guarded profile is being remeasured; `None` is
retained as the owner's selected default, but its growth qualification is open.
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
The full performance, determinism and failure matrix must qualify the new
writer before this result is accepted. The M1 growth ratchet remains required.

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

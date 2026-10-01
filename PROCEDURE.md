# PROCEDURE — the build-time record (deliverable 5)

Build: Drop 3 "Constable" (`addon.constable`), built 2026-09-02 locally.
Consensus gate APPROVED before build (architect: approve-with-notes; critic:
approve). This file records the pre-build checks, the verdicts, the critic
fixes applied during the build, and the declared A5b process gate. Code is
MIT; docs CC-BY-4.0.

## 1. Gift dup-check record (dedup law, SKILL.md §Dedup 1)

`gift-dup-check.sh "constable" "injection-defense kit"` was run 2026-09-02
pre-PRD and returned CLEAR: the script's broad keyword flags were false
positives (rocm-systems, profile README); no injection-defense artifact
existed in the estate. The a2a-bridge gift is auth-hardening — a different
class. The dup record is quoted from the PRD of record; the build added no
new artifact class beyond the PRD's scope (doctrine + corpus + checker in
one fused repo, port 4902).

## 2. Consensus verdicts (summarized)

- **Architect: APPROVE-WITH-NOTES.** Notes applied in this build:
  (a) contribution gates for incoming fixture PRs (A2, A3, A5a
  literal-regex-only) are stated in the README rules of engagement and are
  real, runnable gates — not advice; (b) the A4 scope note — the known-answer
  run proves the checker executes its own labels, NOT efficacy — is stated
  in the README and pinned by the docs test; (c) the taxonomy-closure clause
  (taxonomy derived only from public history; no hint channel via a
  privately-known-but-unfixed class) is stated in docs/DOCTRINE.md and held:
  worked examples cite only merged fixes (PR 333, ADR-034) and our own two
  origin bugs.
- **Critic: APPROVE.** Non-blocking notes, all applied during this build:
  1. A5b's "(see A9 rules)" was a dangling reference — A5b now points at the
     contribution gates in Deliverable 4 (README, "Contribution gates"),
     which is where extension-time adjudication is defined.
  2. The A4 non-efficacy sentence is now pinned by the SAME docs test that
     pins the receipt banner (`tests/test_docs_pins.py`).
  3. The shape-table phrase "weakest standing" for option (b) — adjudicated
     as EVIDENCED rather than struck: option (b) (docs/pattern gift, no
     running instrument) satisfies Wave-A invariant 2 only through its
     receipted-knowledge half, so it is weaker on the invariant than option
     (c), which satisfies both halves (working instrument AND receipted
     knowledge). The PRD table is the consensus record and stands; this
     entry supplies the missing evidence for the comparative. Verdict (c)
     unchanged.
  4. A2's "(where applicable) a typed negative" is now deterministic: every
     defense pattern (engine rule) carries at least one typed negative, and
     attack-class entries carry them wherever a benign lookalike exists —
     in this corpus every class has a lookalike, so every class carries at
     least one. The rule is stated in `corpus/README.md` and enforced by
     `tests/test_corpus_integrity.py`.

## 3. A5b — fresh-adversary pass (DECLARED process gate, not a test)

Status: **run 2026-09-02 (adjudicated FAIL, four smuggles) → blocking fixes
applied → acceptance battery re-run green → round-2 fresh-adversary
confirmation PASS with six required follow-ups → follow-ups applied and
regressed green (§3.1, Run 3).** The reports of record are
`PROCEDURE-A5B-REPORT.md` (round 1) and `PROCEDURE-A5B-ROUND2.md` (round 2).
A5b is a reviewer who did not build the checker attempting to smuggle
payloads past it through its own inputs and output handling (fixture bytes,
scan paths, report fields, service envelope). The pass reports attempts
made, smuggles achieved (target: zero), and fixes applied.

- **Adjudicator: the independent fresh-adversary reviewer of record**
  (assigned at the gate per the approved plan, not by the builder); their
  full report — attempts table, smuggle list, required fixes, verdict — is
  `PROCEDURE-A5B-REPORT.md` in this directory.
- **Extension-time rule:** A5b also runs on every corpus contribution,
  under the same contribution gates defined in Deliverable 4 (README,
  "Contribution gates") — a fixture PR that smuggles a payload past the
  checker's own inputs/outputs is refused on the same terms.
- **Builder pre-work supplied for the adjudicator:** the engine's inputs are
  constrained by construction — scanned files are read as opaque bytes and
  only matched against literal patterns compiled at load; findings quote
  minimal spans; the service applies per-method param allowlists,
  control-character refusal, and body caps; nothing from scanned content
  re-enters the engine as code. The adjudicator's job is to break that
  sentence.

### 3.1 A5b run + fix round (2026-09-02)

**Run 1 — adjudicated FAIL.** The full report of record is
`PROCEDURE-A5B-REPORT.md` (fresh-adversary reviewer, independent session,
read-only probes + scratch-copy attack battery). Verdict: four smuggles
achieved against the pre-fix build — S-1 (text-report injection via a
hostile filename), S-2 (indefinite hang via a FIFO in a scanned dir or
under corpus/, plus the symlink-loop crash, E6), S-3 (scoped-root escape +
content oracle through the contribution path: traversal, absolute, and
symlinked fixture values), S-4 (a runnable getattr-concat attack certified
as a benign typed negative through all gates). Execution surface (A5a) and
service request parsing survived the whole battery.

**Fix round — all four blocking fixes applied + the report's non-blocking
items.** Local-only; nothing published.

- S-1 (`engine.py` `_escape_report_text` + the `--text` writer): control
  characters in scanned-data paths and excerpts are emitted as `\uXXXX` in
  text mode; JSON mode untouched.
- S-2 (`engine.py` `_readable_regular`/`scan_file`/`_iter_target_files`/
  `scan_paths`/`corpus_hash`; `server.py` `_t_scan`): only REGULAR files are
  ever opened (`stat.S_ISREG` + `OSError` guards); non-regular targets are
  counted in a new always-present `files_skipped` report field, printed
  loudly in text mode, and never opened — no hangs, no tracebacks; the A2
  corpus-tree hygiene gate fails the build on any non-regular or escaping
  entry under corpus/.
- S-3 (`engine.py` `resolve_fixture`, used by `known_answer` and by the A2
  gate `tests/test_corpus_integrity.py`): fixture values must be clean
  relative paths that resolve inside corpus/fixtures — traversal, absolute
  paths, and symlink escapes are named integrity errors.
- S-4 (`tests/test_corpus_integrity.py` S-4 gate + README rules of
  engagement): pass/reject fixture content is mechanically scanned in
  normalized and whitespace-joined forms for runnable-execution
  construction (getattr/eval/exec/compile/__import__, os.system shapes,
  new Function, literal+literal name assembly); a hit fails the build,
  and every typed negative additionally requires human review (residual:
  general evasion is undecidable — stated in the README).
- Non-blocking: `RecursionError` added to the service's json-parse
  except-clause (server.py, portability); README documents the
  unauthenticated loopback service surface (any local process can scan any
  user-readable path; 127.0.0.1-only by design; run only on trusted hosts).
- Gate-surface note: the A5a stdlib-import allowlist gained `stat` for
  engine.py (read-only file-mode metadata for the S_ISREG guard); the
  banned execution surface is unchanged.

**Run 2 — acceptance battery re-run against the fixed build (2026-09-02),
all green:**

- S-1 repro: hostile ANSI+newline filename in a scanned dir → text report
  shows `\u001b`/`\u000a` escapes, zero raw ESC bytes, zero forged report
  lines, exactly one real `fix:` line; JSON mode re-parses with raw strings
  unchanged.
- S-2 repros: FIFO `pipe.py` in a scanned dir → exit 0 in 0.06s with the
  loud skip line and `files_skipped: 1`; FIFO passed directly → skipped and
  counted; FIFO under corpus/ → `--known-answer` completes in 0.07s (no
  hang) and the A2 hygiene gate fails the build naming the FIFO; symlink
  loop → skipped and counted, exit 0, no traceback.
- S-3 repros (scratch build): `../` traversal, absolute path, and symlinked
  fixture each fail the A2 gate with a named reason AND make
  `engine --known-answer` emit a `fixture rejected: …` line at exit 2.
- S-4 repro (scratch build): the C2 getattr-concat payload labeled `pass`
  fails the corpus — A2 module exit 1 naming "runnable-execution
  construction in a benign fixture: dynamic evaluator / getattr / import
  call [exact]; string-literal + string-literal concatenation
  [whitespace-joined]".
- Regression: full unittest suite 63/63 OK on two consecutive runs (60
  original + 3 new A5b gate tests); live adversarial matrix 10/10 on
  127.0.0.1:4902 (413+close, 408+close, chunked 400, control-chars 400,
  unknown tool 400, 20-req flood all 200, bind conflict exit 78, privacy
  scans clean); A6 determinism byte-identical runs + 4-parallel (report
  sha256 `bc932b84324ff7c4e1adc10387d332c11561005eb42ed27a3cb308d5d7a388a8`,
  re-pinned in the ALLOWLIST with the reason); corpus sha256 unchanged
  (`7866d02301d3d094e648e78cba6c24ce3c216b382543da425baf0ee4c56a40d3` — no
  corpus byte moved in the fix round); A1 validator 0 errors / 0 warnings
  against the real validator (their dev-branch clone pinned at
  `7ae7bf87eea2617b825ca16d01fa4337445fbf6d`, tree left clean); A9 golden
  extension green inside the suite.

**A5b status after the fix round: PASS pending fresh-adversary
confirmation.** The builder has applied all four blocking fixes and re-run
the full battery with the results recorded above; the declared acceptance
condition is the independent re-run of the A5b battery by a fresh
adversary, which remains the gate-closing step.

**Run 2 (the gate-closing fresh-adversary confirmation) — PASS, 2026-09-02.**
Record: `PROCEDURE-A5B-ROUND2.md` (a second independent session; all ten
recorded repros recreated from scratch on a fresh copy — 10/10 dead — plus
nine new attack lines: zero completed smuggles, nine findings/notes, six
required follow-ups). The round-2 verdict statement, quoted for the record:
under the merged contract (human review of every typed negative is
load-bearing) F-7 is a demonstrated insufficiency of the heuristic layer,
not a completed smuggle; if the bar were "zero mechanical bypass payloads
exist," F-7 would have flipped the verdict to FAIL.

**Run 3 — the six round-2 required follow-ups applied (2026-09-02,
same day, local-only).** PRD contract intact: acceptance criteria A1-A10
unweakened, corpus entries unchanged at 27 (A4 known-answer counts 13/12/2
unchanged). Per-follow-up record:

1. **F-7 / S-4 extension** (`tests/test_corpus_integrity.py` S4_CHECKS and
   the s4 normalizer; README A2 gate list). The round-2 payload list is
   covered verbatim: alias-then-call (`os.system`/`os.popen` TOKEN pattern,
   paren not required, plus assignment-of-a-bare-executor), `os.posix_spawn`
   /`posix_spawnp` (posix_spawn family added), bare `Function(` (the
   `new\s+Function` shape widened), `child_process.execSync` (child_process
   exec/spawn family + execSync-in-any-shape, aliased receivers included),
   and `globalThis[...]` dynamic-index execution with unicode-escaped names
   (the normalizer now decodes JS `\uXXXX` escapes and
   `String.fromCharCode(...)` before pattern-checking, as extra
   *-unescaped forms). The S-4 gate test docstrings no longer overclaim:
   the gate is stated as a HEURISTIC layer that pins the constructions the
   mechanical layer CAN name — the README's mandatory human review of every
   typed negative is the load-bearing certification. New gate-fire tests
   pin all five payloads (plus aliased-receiver, fromCharCode, and
   bare-evaluator-alias variants).
2. **F-8 / hash injectivity** (`engine.py corpus_hash`). Every digest
   record is now LENGTH-FRAMED (`b"<len>:<rel>:" + b"<len>:<content>:"`),
   so the round-2 splice (fixture content carrying NUL + a forged relpath +
   a second fixture's bytes) can no longer digest identically to a
   two-fixture corpus. Regression test builds both spliced and clean
   corpora and asserts different hashes
   (`test_corpus_hash_framing_resists_the_round2_splice`).
3. **F-1 / escape coverage** (`engine.py _escape_report_text`). The escape
   class now covers 0x7F-0x9F (DEL + the whole C1 range — U+009B is a live
   CSI introducer and U+0085 a line break on C1-honoring terminals),
   U+2028/U+2029, U+202E (RTL override), and U+200B (zero-width space).
   Pinned by byte-level `--text` output assertions (raw `C2 9B`, `C2 85`,
   `E2 80 A8/9`, `E2 80 AE`, `E2 80 8B`, ESC all refused; `\uXXXX`
   spellings required; exactly one real `matched:`/`fix:` pair) covering
   both carriers — filename and excerpt (`tests/test_docs_pins.py`).
4. **F-4 / corpus read bounds** (`engine.py corpus_hash`, `load_corpus`).
   corpus_hash caps per-file reads at MAX_FILE_BYTES (the round-2 3 GB
   unindexed junk file previously drove max RSS to 3.24 GB); load_corpus
   refuses a corpus.json over MAX_INDEX_BYTES with a named error. Pinned
   by the bounded-hash regression (hash of a >cap tree equals the hash
   after truncating the junk to the cap — bytes beyond the cap are never
   read) and the oversized-index refusal test.
5. **F-5 / findings caps** (`engine.py _scan_file_limited`/`scan_paths`/
   `build_report`/`main`; `server.py _t_scan`). Per-file cap
   MAX_FINDINGS_PER_FILE = 500, per-report cap MAX_FINDINGS = 1000, with
   honest `findings_truncated`/`findings_suppressed` report fields always
   present, a named text-mode banner ("findings capped at 1000 — N further
   findings suppressed"), and the suppressed count in the stdout log line.
   The round-2 amplifier (one 8 MB file → 254,200 findings → 649 MB RSS →
   159 MB report) now degrades to a bounded, honestly-labeled report.
   Pinned by `tests/test_resource_bounds.py` (exact cap/suppression
   arithmetic across both caps, report-field honesty, CLI banner).
6. **known_answer fails missing fixtures** (`engine.py known_answer`).
   A contained-but-absent fixture is a named failure
   ("fixture file missing: …") at exit 2 for every label — never the
   round-2 phantom "clean" negative (F-6a). Pinned for pass- and
   detect-labeled ghosts (`tests/test_known_answer.py`).

**Run 3 — F-7 payload coverage table (the five round-2 payloads against the
EXTENDED gate):** all five are now caught MECHANICALLY by the S-4 gate
(the engine's line rules remain blind to all five, as declared — the gate
is the layer that catches them):

| Round-2 payload | S-4 gate (extended) | Engine rules |
|---|---|---|
| P1 `run = os.system` then `run(cmd)` | CAUGHT — os system/popen token (call or alias shape) | blind (as declared) |
| P2 `os.posix_spawn(...)` | CAUGHT — os posix_spawn/exec/spawn call | blind (as declared) |
| P3 bare `Function("return 40 + 2")()` | CAUGHT — Function(...) dynamic construction (new or bare) | blind (as declared) |
| P4 `child_process.execSync(userCmd)` | CAUGHT — child_process family + bare/aliased execSync | blind (as declared) |
| P5 `globalThis["\u0065val"]("40 + 2")` | CAUGHT — dynamic-index over the global object + bracketed string-name call (and the unescaped forms expose `eval`) | blind (as declared) |

Honest residual (probed this round, documented, NOT gate-pinned as caught):
runtime-encoded evaluator names beyond the normalizer (atob/base64 decode)
and constructor indirection (`Function.bind` chains) still SLIP the
mechanical gate — the human-review layer stays load-bearing for exactly
these, as the README states. Adjacent probes hardened during the round:
aliased receivers (`cp.execSync(`, `m.system(` — the dot no longer defeats
the lookbehinds), importlib module aliases, optional-chained global access,
and template-literal name assembly (backtick concat now matches).

**Run 3 — re-pin list (both legitimate, both documented in the ALLOWLIST):**

- corpus sha256 `7866d02301d3d094e648e78cba6c24ce3c216b382543da425baf0ee4c56a40d3`
  → `d602a42b7c882e4a2183536d9e967d1fb1670a4c72711eac013a43d9154a8123`: the
  digest FRAMING changed (F-8 length-prefixing) — no corpus byte moved; the
  old value is kept in the ALLOWLIST as the historical fix-round record
  cited in §3.1 Run 2.
- report sha256 `bc932b84324ff7c4e1adc10387d332c11561005eb42ed27a3cb308d5d7a388a8`
  → `96356546bf9b7f53df2ce7db5c954a30d78f06a1bec0b9992417961f82075d07`: the
  report object now always carries `findings_truncated`/
  `findings_suppressed` (F-5); the old value is kept as the superseded
  S-2-round record.

**Run 3 — regression evidence (all green):** full unittest suite 74/74 OK
on two consecutive runs (63 prior + 11 new gate tests); live adversarial
matrix 10/10 on 127.0.0.1:4902 (run-matrix.sh, real process, port released
after); A6 determinism: two runs byte-identical + 4-parallel byte-identical
(report sha256
`96356546bf9b7f53df2ce7db5c954a30d78f06a1bec0b9992417961f82075d07`,
re-pinned above); A1 validator 0 errors / 0 warnings against their
dev-branch clone pinned at
`7ae7bf87eea2617b825ca16d01fa4337445fbf6d`, their tree left clean; A4
known-answer 100% UNCHANGED (attacks 13/13, negatives 12/12, defenses 2/2
— no corpus byte moved); A9 golden extension green inside the suite;
battery spot-check: S-1..S-4 original repros re-run dead (text-mode forgery
refused, FIFO/loop skips loud and fast, containment rejections named, C2
getattr-concat gate-fail).

**A5b status after Run 3: gate CLOSED.** Round-2 confirmation PASS + all six
required follow-ups applied and regressed. The residual is declared, not
hidden: the S-4 mechanical layer is heuristic; human review of typed
negatives remains load-bearing.

## 4. Build gates run (evidence recorded 2026-09-02, build time)

1. **A1 validator 0/0** — `sh run-validator-check.sh <2.0.0-alpha-clone>`
   against the real `src/sdk/addons/validation.ts` validator; their repo
   pinned at dev HEAD `7ae7bf87eea2617b825ca16d01fa4337445fbf6d`
   ("Merge pull request #335") at build time. Result: issues `[]`,
   `Test Files 1 passed (1)`, `Tests 1 passed (1)`, exit 0; their tree left
   clean (spec removed via trap, `git status --porcelain` empty).
2. **Suite green twice** — `python3 -m unittest discover -s tests`:
   `Ran 60 tests ... OK` on two consecutive runs (includes the A9 golden
   end-to-end and the in-process adversarial HTTP set).
3. **A3 mechanized scan green** — 5/5 checks: absolute paths all under
   allowlisted prefixes; URL hosts + hostname-shaped tokens all suffix-
   allowlisted (loopback 127.0.0.1 is explicitly the only IP allowed);
   zero hex-runs >=16 and zero provider-token shapes; all PR/issue/sha/
   their-path citations members of the ALLOWLIST citation set.
4. **A5a gate green** — tokenize-strings-stripped grep + AST over
   engine.py and server.py: no execution surface, no dynamic builtins,
   every re.compile on a literal constant, every open() binary.
5. **A4 known answer 100%** — attacks 13/13, typed negatives 12/12,
   defense exemplars 2/2; corpus sha256
   `7866d02301d3d094e648e78cba6c24ce3c216b382543da425baf0ee4c56a40d3`.
6. **A6 determinism** — same target tree, two runs byte-identical, report
   sha256 `bc932b84324ff7c4e1adc10387d332c11561005eb42ed27a3cb308d5d7a388a8`
   (re-pinned after the A5b fix round: the report object now always carries
   `files_skipped`, A5b S-2; the corpus sha256 below is unchanged);
   4-parallel re-run: byte-identical outputs.
7. **Live adversarial matrix 10/10 on 127.0.0.1:4902** (run-matrix.sh,
   real process): service up; oversized 413 + Connection: close advertised;
   lying Content-Length 408 + close (production 30s path, unpatched);
   chunked 400; control-chars 400; unknown tool 400; 20-req concurrent
   flood all 200; privacy scan (no home path in outputs, redaction live);
   real round-trip carries the receipt banner; bind conflict exit 78;
   whole-tree privacy scan clean.
8. **A9 golden extension end-to-end green** — contributed rule R7 +
   fixtures + matrix row on a scratch copy: extended engine known-answer
   14/14 attacks, 13/13 negatives, all_pass, literal-regex gate holds on
   the extended source; shipped tree unchanged (27 entries / 6 classes).
9. **A5b** — run 2026-09-02 by the independent adjudicator of record:
   adjudicated FAIL with four smuggles (report:
   `PROCEDURE-A5B-REPORT.md`); all four blocking fixes + the recommended
   hardening applied the same day; the acceptance battery (all four repros
   + full regression) re-run green — see §3.1 for the complete record and
   the gate-closing condition (independent fresh-adversary confirmation).

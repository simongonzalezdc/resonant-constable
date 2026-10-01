# PROCEDURE A5b — ROUND 2: independent fresh-adversary confirmation pass

Gate: PRD A5b, closing run. This pass was performed by a **second fresh
adversary** — a session that neither built the Constable gift nor applied the
fix round, and that trusted neither the prior scratch ranges nor the fix
round's own claims: every repro below was recreated from scratch on a new
scratch copy, and every fix was attacked again with NEW payloads.

- Date: 2026-09-02
- Build under attack: `addons/constable-gift` as shipped 2026-09-02 04:44
  (engine.py + server.py fix round; corpus sha256
  `7866d02301d3d094e648e78cba6c24ce3c216b382543da425baf0ee4c56a40d3`).
- Scratch: `/tmp/a5b-r2-fresh/build` — a byte copy of the shipped tree,
  baseline-verified before attack (known-answer all_pass 13/13 + 12/12 + 2/2,
  corpus hash matches the pin, full suite 63/63 OK). The service was booted
  from THIS copy on 127.0.0.1:4902 and torn down after the pass; port
  released. The shipped tree was never modified (verified: no shipped-tree
  file changed during the pass). The entire scratch tree was deleted at the
  end (probes removed). Python 3.14.7, node available.
- Inputs of record: `PROCEDURE-A5B-REPORT.md` (round-1 adjudication, smuggles
  S-1..S-4) and `PROCEDURE.md` §3.1 (fix round + acceptance battery).

## 1. Battery re-run — all ten recorded repros, fresh, verbatim (JOB 1)

Every repro was recreated from scratch on the fresh scratch copy. Verdicts
are against the smuggle's OWN success criterion from round 1: PASS here means
**the smuggle is dead** (the recorded failure no longer occurs).

| # | Repro (recorded smuggle → attack) | Fresh-run actual result | Verdict |
|---|---|---|---|
| 1 | **S-1** — ANSI+newline hostile filename in a scanned dir, `--text` mode (forged report lines / terminal escape injection) | exit 0; **zero raw ESC bytes** in stdout (LC_ALL=C grep); the path renders as ONE physical line with `\u001b[31m\u000a` escapes; line-anchored counts: exactly 1 real `matched:` line and 1 real `fix:` line — zero forged lines. JSON mode re-parses cleanly with the raw control characters preserved in the string value. | **smuggle dead — PASS** |
| 2 | **S-2** — FIFO named `pipe.py` planted INSIDE a scanned dir (round 1: scan hung forever, exit 124) | exit 0 in 0.106 s; loud skip line ("skipped (not regular files … never opened): 1"); JSON `files_scanned: 1, files_skipped: 1` — the one real file still scanned | **smuggle dead — PASS** |
| 3 | **S-2** — FIFO passed directly as a scan path | exit 0 fast; `files scanned: 0, skipped: 1` | **smuggle dead — PASS** |
| 4 | **S-2** — FIFO planted under corpus/ (round 1: `known_answer` hung forever, C4) | `--known-answer` completes in 0.14 s, exit 0, all_pass true, corpus hash unchanged — the FIFO is never opened | **smuggle dead — PASS** |
| 5 | **S-2** — same planted FIFO vs the A2 hygiene gate | gate FAILS the build: `corpus tree hygiene failures: … pipe-fifo.py: not a regular file (format 0o10000) — would hang or poison the corpus read set` (FIFO removed after the repro; hash re-verified against the pin) | **gate holds — PASS** |
| 6 | **S-2/E6** — symlink loop `loop.py → itself` in a scanned dir (round 1: unhandled OSError crash, exit 1 + traceback) | exit 0, `skipped: 1`, zero tracebacks on stderr | **smuggle dead — PASS** |
| 7 | **S-2** — hostile scan (tree containing the FIFO) through the LIVE service on 127.0.0.1:4902 (round 1: pinned a service thread forever) | service booted from the scratch copy; `constable.scan` returned 200 in **0.03 s** with `files_skipped: 1`, `files_scanned: 1`. Extra: `/dev/zero` as a direct path → 200, `files_skipped: 1` (char device never read). Service torn down after the pass. | **smuggle dead — PASS** |
| 8 | **S-3** — `../` traversal fixture (`../../../../…/tiny.py`) | engine `--known-answer`: exit 2, `fixture rejected: '..' traversal rejected (fixture must stay under corpus/fixtures)`; A2 gate exit 1 with the same named reason | **smuggle dead — PASS** |
| 9 | **S-3** — absolute-path fixture (`/tmp/…/tiny.py`, the round-1 near-miss C1b) | engine exit 2, `fixture rejected: absolute fixture path rejected…`; A2 gate exit 1 | **smuggle dead — PASS** |
| 10 | **S-3** — symlinked fixture inside fixtures/ → outside file (round-1 C1c) | engine exit 2, `fixture rejected: fixture resolves outside corpus/fixtures (symlink escape rejected)`; A2 gate exit 1 | **smuggle dead — PASS** |
| 11 | **S-4** — the C2 getattr-concat payload (`fn = getattr(os, "sys" + "tem"); fn(cmd)`) labeled `pass` | engine known_answer stays blind (declared: line rules cannot see it) — **the S-4 content gate catches it**: build fails with `runnable-execution construction in a benign fixture: dynamic evaluator / getattr / import call [exact]; string-literal + string-literal concatenation … [exact + whitespace-joined]`. Corpus restored after the repro. | **smuggle dead — PASS** |

(11 rows = the ten recorded repros; rows 4 and 5 are the two halves of the
corpus-FIFO repro — engine side and gate side.)

**Battery result: 10/10 repros re-verified dead on a fresh scratch copy.**

## 2. New-attack inventory (JOB 2 — bounded window against the FIXED surfaces)

Legend: identical to round 1 — SMUGGLE = contract broken per the A5b bar;
FINDING = a real gap or weakness that does not complete a smuggle under the
merged contract; RESISTED = expected failure observed; NOTE = logged
observation.

### (a) `_escape_report_text` — the escape covers only ord < 0x20 or == 0x7F

| # | Attempt | Actual result | Verdict |
|---|---|---|---|
| F-1a | Filename carrying C1 controls: U+009B (CSI — the 8-bit ANSI escape introducer) and U+0085 (NEL — C1 next-line), plus U+202E (RTL override) and U+200B (zero-width space) | ALL pass **raw** into the text report — byte-verified: `C2 9B`, `C2 85`, `E2 80 AE`, `E2 80 8B` present unescaped in stdout. Impact is terminal-dependent: on C1-honoring terminals (xterm family) U+009B+`31m` is a live SGR injection and U+0085 is a LINE BREAK — i.e. report-line forgery returns on those terminals; on macOS Terminal.app (this gift's operator platform) C1 in UTF-8 renders inert and no byte-level line forgery occurs. JSON mode escapes all of them (`\u009b` etc.). The fix's docstring claims "control characters … become \uXXXX" — C1 ARE control characters and are not covered. | **FINDING (platform-dependent terminal injection; fix: escape all ords 0x7F–0x9F + U+2028/U+2029)** |
| F-1b | Same C1/CSI payload inside an EXCERPT (file content line containing U+009B — not a `splitlines()` boundary, so it survives into the minimal-span quote) | excerpt carries raw `C2 9B` + `31;1m` tail into text output (cat -v verified) — same platform-dependent injection surface as F-1a, from content rather than filename | **FINDING (same fix; excerpt side)** |
| F-1c | Literal `\u001b` TEXT in a filename (double-encoding ambiguity) | after escaping, attacker's literal `\u001b[32m` text is byte-identical to a genuinely escaped ESC — a reader cannot distinguish real control chars from literal text. Display ambiguity only; no forgery. | NOTE |
| F-1d | U+0085 / U+2028 / U+2029 in file CONTENT (line-number skew) | Python `splitlines()` treats them as line boundaries → one visual line counts as 2+ lines; line numbers in findings skew vs other tools | NOTE (minor) |

### (b) the S_ISREG path — TOCTOU, devices, huge files, unbounded reads

| # | Attempt | Actual result | Verdict |
|---|---|---|---|
| F-2 | TOCTOU: atomically swap regular ↔ FIFO at the same path (rename) to land a FIFO inside the `stat → open` window of `_readable_regular`/`scan_file`; hammer at ~80k flips while 261 timed scans ran | **0 hangs in 261 attempts** — the µs-wide window held every time. A won race would at worst re-create the round-1 hang (DoS), not an escape. | RESISTED (bounded; TOCTOU residual is inherent and now µs-wide) |
| F-3 | /dev special files that ARE regular; /proc-style traps | macOS has no /proc; /dev/zero and /dev/stdout are char devices → skipped unread (verified through the live service: 200, `files_skipped: 1`). `/dev/fd/0` reports S_ISREG=True **only when the service's own stdin is a regular file** — then it is a bounded ≤8 MB read of operator-supplied boot-time stdin; not attacker-reachable content. | RESISTED |
| F-4 | Huge file under corpus/ NOT referenced by the index (3 GB sparse `junk-sparse.bin`) | `corpus_hash` slurps the file WHOLE (`handle.read()`, no cap — contrast scan_file's 8 MB cap): `--known-answer` completed but **max RSS 3.24 GB**, linear in junk size. Contributor-reachable: the A2 fixture-size cap covers only INDEXED entries; the hygiene gate checks regularity only. The docstring says "a hostile corpus cannot hang the hash" — it cannot hang, but it can OOM the CI that runs the suite. | **FINDING (memory-DoS; fix: cap corpus_hash reads at MAX_FILE_BYTES and bound corpus.json size in load_corpus)** |
| F-5 | Findings amplification inside the read cap: one 46 MB file of 32-byte matching lines (read capped at 8 MB as designed) | the findings LIST is O(matches): 254,200 finding dicts → **649 MB RSS** → **159 MB JSON report** from a single ≤8 MB-capped scan. Reachable via the service by any local process (scan a crafted user-readable file). | **FINDING (amplification; fix: per-file and per-report findings caps)** |

### (c) `resolve_fixture` — encoded traversal, separators, case folding, hardlinks

| # | Attempt | Actual result | Verdict |
|---|---|---|---|
| F-6a | Percent-encoded traversal (`attacks/%2e%2e/%2e%2e/tiny.py`), backslash separators (`attacks\..\..\tiny.py`), and any nonexistent contained path labeled `pass` | all three: containment PASSES (they are literal names), `scan_file` finds nothing → engine known_answer reports the entry **"clean", all_pass True** — a phantom negative. The A2 gate catches every variant (`fixture file missing`) → not mergeable. | **FINDING (engine-side robustness: known_answer should fail missing fixtures itself; gate-covered today)** |
| F-6b | Case-folded alias (`ATTACKS/C1-SHELL-CONCAT.PY` on case-insensitive APFS) | resolves to the real file INSIDE the root; detect label still fires; gate green — aliasing within the root, no escape | RESISTED |
| F-6c | Inner dot-segments staying inside (`attacks/../attacks/c1-shell-concat.py`) | rejected — ANY `..` segment is refused regardless of destination | RESISTED (conservative, correct) |
| F-6d | **Hardlink** inside fixtures → outside-origin content (the task's named question) | resolve/containment is blind to hardlinks (realpath has no provenance): known_answer read the outside content, labeled it clean, all_pass True, and digested the outside bytes into corpus_hash; EVERY content gate green — only the MATRIX-row bookkeeping test tripped, which a normal PR adds. **But reachability is closed: git cannot carry hardlinks** (verified: clone materializes an independent file, st_nlink 3→1), and local write access to the tree is not a privilege boundary (such an actor can write fixtures directly). | NOTE (analyzed-and-closed; optional info-level hygiene signal: flag st_nlink > 1) |
| F-6e | Invalid UTF-8 / raw bytes in corpus.json (overlong-shaped payload) | engine crashes with a raw UnicodeDecodeError traceback, exit 1, no report (crash, not hang). The A2 gate crashes the same way → the build fails → not mergeable. | NOTE (robustness; clean-refusal would be nicer; gate-covered) |

### (d) the S-4 gate's six patterns — dynamic-execution constructions NOT covered

All payloads below were (i) scanned by the engine, (ii) run through
`s4_scan_benign_fixture` (both normalized forms), and (iii) PROVEN EXECUTING
with harmless echo/markers on this machine.

| # | Payload (as a candidate "benign typed negative") | Engine findings | S-4 gate hits | Executes? |
|---|---|---|---|---|
| F-7 P1 | `run = os.system` + `run(user_cmd)` — alias-then-call (R1 and S-4's os-shape both require the paren directly after `system`) | 0 | 0 | YES (`P1-EXECUTED-via-alias` printed) |
| F-7 P2 | `os.posix_spawn("/bin/sh", ["/bin/sh", "-c", user_cmd], os.environ)` — S-4's exec/spawn shape covers `execv*`/`spawn*` but not `posix_spawn`/`posix_spawnp` | 0 | 0 | YES (`P2-EXECUTED-via-posix_spawn` printed) |
| F-7 P3 | bare `Function("return 40 + 2")()` — engine R2 and S-4 both match only `new Function(` | 0 | 0 | YES (node: 42) |
| F-7 P4 | `child_process.execSync(userCmd)` — engine R1 matches `child_process.exec(` only; S-4 has no child_process shapes at all | 0 | 0 | YES (node: marker printed) |
| F-7 P5 | `globalThis["\u0065val"]("40 + 2")` — JS unicode-escaped identifier; the gate sees no `eval(` token in the raw text | 0 | 0 | YES (node: 42) |

**End-to-end hostile-PR simulation (the round-1 C2 protocol, exactly):** P1+P2
installed as `pass` typed negatives (fixtures + corpus.json entries + MATRIX
rows + ALL count pins updated exactly as any corpus-growing PR must —
test_known_answer 12→14, test_addon 27/12→29/14, golden 13→15):

- engine `--known-answer`: exit 0, all_pass — both executing attack shapes
  certified clean;
- A2 integrity module: **OK** (containment, hygiene, S-4 content gate,
  applicability, matrix — all green);
- FULL 63-test suite: **OK**.

So the S-4 channel is **mechanically reopened** by new payloads. What keeps
it from being a completed smuggle is the merged contract's declared
compensating control: the README rules of engagement require HUMAN REVIEW of
every typed negative (the fix round itself declares the mechanical layer "a
heuristic layer, not a decision procedure — general evasion is undecidable").
`run = os.system` does not survive a human glance — but the S-4 gate test's
docstring overclaims ("the corpus must never certify a runnable attack shape
as a benign lookalike") and MUST be aligned with that declared residual, and
the named pattern gaps are concrete and fixable. Decorator/format-string
tricks were examined and add nothing beyond the above (f-string
`f"{os.system('x')}"` is engine-caught by R1; `\u0067etattr`-style escapes do
not parse as Python identifiers; numexpr/ast.literal_eval are not stdlib
execution surfaces). | **FINDING, S-4 class (mechanical layer insufficient; stopped by the declared human-review gate; fix: extend S4_CHECKS per payload list + fix the docstring overclaim)** |

### (e) corpus_hash / digest

| # | Attempt | Actual result | Verdict |
|---|---|---|---|
| F-8 | **Framing splice** — corpus_hash records are `relpath \x00 content \x00` with NO length prefix, and file CONTENT may contain NUL. Constructed two different corpora with NO hash search: A = {corpus.json J, a.py=c1, b.py=c2}; B = {corpus.json J, a.py = c1 ‖ \x00 ‖ "fixtures/attacks/b.py" ‖ \x00 ‖ c2} | **hash(A) == hash(B) == `3029444bea868b25364fb87db41cbe71d3403146af92a766704d27d3af461fc8`** (manually cross-checked against the raw stream). A two-fixture corpus and a one-fixture corpus are digest-identical BY CONSTRUCTION. Consequence: "corpus_hash unchanged ⇒ no corpus byte moved" is forgeable — the ALLOWLIST pin's evidence value is not cryptographically backed against a corpus author who controls fixture bytes (trailing NUL+name bytes in a fixture are unremarkable to review; detect-labeled fixtures are not content-scanned at all). | **FINDING (digest ambiguity; fix: length-prefix the name and content per record, then re-pin)** |
| F-9 | Pin swap: can the pinned hash in ALLOWLIST be swapped? | the pin is plain ALLOWLIST content; the A3 entropy gate requires 16+ hex tokens to be allowlisted MEMBERS — but updating the membership is part of the same PR, so the pin has no mechanical external anchor. This is a pre-existing property of the trust chain (it ends at human review), unchanged by the fix round; F-8 above is what makes even an honest pin forgeable. | NOTE (analysis) |

## 3. Adjudicator verdict

**A5b: PASS — the gate closes, with required follow-ups recorded.**

- **Battery:** 10/10 recorded repros re-verified dead on a fresh scratch
  copy, including the live-service half (hostile scan returned in 0.03 s
  where round 1 pinned a thread forever). S-1, S-2 (all five surfaces incl.
  E6), S-3 (all three shapes), and S-4's recorded payload are each dead.
- **New smuggles: zero completed.** Nine attack lines were run against the
  fixed surfaces; every one either RESISTED, was stopped by a gate, or is
  recorded as a FINDING that does not complete a smuggle under the merged
  contract: F-1/F-1b (C1 escape gap — no byte-level line forgery on the
  target platform, terminal-dependent injection elsewhere), F-2 (TOCTOU —
  not won in bounded testing), F-4/F-5 (resource bounds — DoS-adjacent, not
  contract-breaking), F-6d (hardlink — mechanically invisible but
  unreachable: git cannot carry hardlinks), F-7 (S-4 mechanical bypasses —
  stopped by the declared mandatory human-review gate), F-8 (hash splice —
  weakens an evidence pin, executes nothing, escapes nothing).
- Stated plainly, per the adversarial duty: **if the bar were "zero
  mechanical bypass payloads exist," F-7 would flip this verdict to FAIL.**
  Under the record's own bar (a smuggle is a contract break through ALL
  load-bearing gates, and the merged rules of engagement make human review of
  every typed negative load-bearing precisely because the mechanical layer is
  declared heuristic), F-7 is a demonstrated insufficiency of the heuristic
  layer, not a completed smuggle.

**Required follow-ups (non-blocking for A5b's closure; blocking for the next
content-touching change):**

1. **S-4 gate:** extend `S4_CHECKS` — `posix_spawn`/`posix_spawnp`; bare
   `Function(`; any `os.system`/`os.popen` token in a benign fixture
   (assignment shape included, paren not required);
   `child_process.{exec,spawn}Sync` family; normalize JS `\uXXXX` escapes and
   `String.fromCharCode` before scanning. Fix the test docstring overclaim
   ("must never certify") to match the README's declared heuristic+review
   residual.
2. **corpus_hash framing:** length-prefix name and content per record;
   re-pin the corpus hash after the change (digest will move by design).
3. **corpus_hash / load_corpus reads:** cap at `MAX_FILE_BYTES` (and a
   corpus.json size bound) — closes F-4.
4. **findings cap:** per-file and per-report finding limits in
   `scan_file`/`scan_paths` — closes F-5.
5. **`_escape_report_text`:** extend to all ords 0x7F–0x9F plus
   U+2028/U+2029 — closes F-1/F-1b on all terminals, not just the
   target platform's.
6. **known_answer:** fail (or loudly mark) entries whose fixture does not
   exist, instead of reporting phantom "clean" negatives — defense in depth
   behind the A2 gate.

Method note: probes ran only against the scratch copy and loopback 4902; the
service was torn down and the port released; the scratch tree (all probe
files, including the executing payloads and hash-lab corpora) was deleted;
the shipped tree was verified untouched. Raw-evidence artifacts quoted above
were captured during the pass and destroyed with the scratch per the
cleanup rule; every number in this file was read from tool output, not from
the fix round's records.

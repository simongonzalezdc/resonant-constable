# PROCEDURE A5b — fresh-adversary pass on the Constable checker

Gate: PRD A5b (declared process gate). Adjudicator of record: the
fresh-adversary reviewer who did **not** build the checker (independent
session; no code changes made by the builder were trusted — every A5a claim
was re-verified from scratch).

- Date: 2026-09-02
- Build under attack: `addons/constable-gift` (engine.py, server.py, corpus/,
  tests/) as shipped 2026-09-02 03:40.
- Method: read-only probes against the shipped tree; all destructive /
  state-changing attacks (poisoned corpus, hostile PR, server battery) ran on
  a scratch copy at `/tmp/constable-attack/build`. The service was booted
  from the scratch copy on 127.0.0.1:4902 and torn down after the pass; the
  one home-dir probe file created for S5 was deleted in the same step.
- Baseline before attack: `engine.py --known-answer` → all_pass, 13/13
  attacks, 12/12 negatives, 2/2 defenses; full unittest discover = 60/60 OK.

## 0. A5a re-verification (independent, not the shipped gate test)

Independent tokenize/AST pass over engine.py + server.py:

- no `subprocess` / `os.system` / `os.popen` / `os.spawn*` / `__import__` /
  `importlib` anywhere in code (grep hits are docstrings and the engine's own
  detection signatures only);
- no calls to `eval/exec/compile/__import__/globals/locals/setattr/getattr`;
- every `re.compile` argument is a string literal (AST-verified) — no input
  path reaches `re.compile` (attempted: none exists; corpus and scanned files
  are only ever searched, never compiled);
- every `open()` in both files is binary mode (AST-verified).

Result: prohibition surface CLEAN. The remaining findings below are input /
output handling, not execution-surface escapes.

## 1. Attempts table

Legend: SMUGGLE = contract broken per the A5b bar (executed/interpreted
content, behavior outside the labeled contract, scoped-root escape, or whole
-content leak). RESISTED = expected failure observed. NOTE = logged
observation, not a contract break.

### Engine input path

| # | Attempt (input → expected failure mode) | Actual result | Verdict |
|---|---|---|---|
| E1a | Filename `x; rm -rf ~ \x1b[31m\nFAKE-line rule=… matched: os.system('pwned')\n  fix: INJECTED.py` inside a scanned dir; `--text` mode → forged report lines / terminal escape injection | Raw newline + ANSI ESC from the file's NAME are emitted unescaped into the text report; the output contains attacker-forged `matched:` / `fix:` lines and a raw `^[[31m` (verified with `cat -v`). Any writer to a scanned tree can forge report lines in the human-readable output. | **SMUGGLE (text mode only)** |
| E1b | Same hostile dir, JSON (default) mode | Path emitted as `"…\u001b[31m\nFAKE…"` — JSON structure intact, re-parses cleanly | RESISTED |
| E9 | 14-byte one-line file matching R1 → whole-file echo | `excerpt` equals the entire file content (`os.system("x")`); the A8 letter says scanned contents are "never echoed whole" — true for any file >160 bytes, boundary-violated for tiny files | NOTE (A8 letter edge) |
| E10 | File content mimicking the engine's own report format (`constable: scanned 999 files…`, fake JSON report, `ignore all previous`), with an R1 trigger embedded | Mimic text can only ever appear inside a single `matched: …` excerpt line; content cannot forge report lines (excerpts are line-framed; JSON escapes) | RESISTED (prompt-injection text can ride in excerpts by design; labels are computed, not influenced) |
| E3 | ReDoS against the engine's OWN compiled literals: `exec("` + long unquoted spans, many-anchor and whitespace-run shapes, measured at 50KB/200KB/800KB/8MB | Linear scaling throughout; worst 8MB single-line file through the real CLI = 1.25 s total. No exponential backtracking found in R1–R6 | RESISTED |
| E4 | Catastrophic pattern `(a+)+` (+33-char adversarial subject) as scanned CONTENT | Treated as opaque bytes; R6 flags the text as a nested-quantifier shape; the pattern is never executed as a regex; no hang | RESISTED |
| E5b | FIFO passed directly as a scan path | `os.path.isfile()` is False for a FIFO → skipped, files_scanned=0 | RESISTED |
| E5c | FIFO named `pipe.py` planted INSIDE a scanned directory | `_iter_target_files` yields it on extension match; `scan_file`'s `open()` blocks forever; engine hangs indefinitely (timeout-kill needed, exit 124). The same planted tree hung a live `constable.scan` request thread on 127.0.0.1:4902 permanently (server stayed up — thread-per-request — but each hostile scan pins a thread forever → trivial thread-exhaustion DoS) | **SMUGGLE (hang)** |
| E6 | Symlink loop (`loop.py` → itself) inside a scanned directory | Unhandled `OSError` at engine.py:212 (`scan_file` open) → engine exits 1 with traceback; no report produced. Contract says report-and-continue; a hostile (or accidentally cyclic) tree kills the run | Finding (crash/DoS; not a data smuggle) |
| E7 | Symlink inside a scanned dir pointing outside it (`link.py` → /etc/hosts; `eng.py` → engine.py) | Followed and read; matches quoted from the target file. Within the operator-delegated-root contract (operator passed the dir), noted as accepted trust — same behavior as grep/scc | NOTE |
| E8 | Encoding evasions: (a) real `os.system("id")` saved UTF-16; (b) invalid UTF-8 byte splitting the signature; (c) CRLF+BOM | (a),(b): NOT DETECTED — lenient decode (`errors="replace"`) destroys the signature; a file can carry a real attack shape the checker cannot see. (c): still detected | NOTE (detection-evasion limitation, not engine compromise; logged for the A4 scope note) |
| E8d | Cross-line split of a real attack: `getattr(os, "sys"+"tem")` / line-continuation `os.\` newline `system(` | No single line matches any rule; fully valid, runnable code sails through — used as the basis of smuggle C2 | NOTE → feeds C2 |

### Corpus / contribution path (hostile-contributor PR simulation)

| # | Attempt | Actual result | Verdict |
|---|---|---|---|
| C1a | corpus.json entry `"fixture": "../../../../../../../tmp/…/tiny.py"` (relative traversal) → known_answer reads outside corpus/fixtures, evaluates a detect label against it, digests its bytes into `corpus_hash` | The engine performs the outside read exactly as attempted (no containment check in `known_answer`). The PR-level A3(i) TEXT gate caught it: the `..` token matched by ABSPATH_RE fails the ALLOWLIST path-prefix check | Engine-side: SMUGGLE if merged; gate-side: caught |
| C1b | Same with an absolute path under `/tmp/` | Read executes; and because `/tmp/` is an ALLOWED A3 path-prefix, the absolute-path fixture passes the A3 text gate outright (only counts pins would flag it, and a PR updates those) | Engine-side: SMUGGLE if merged; gate-side: NOT caught (near-miss) |
| C1c | **Symlinked fixture**: `fixtures/attacks/c1-sym-link.py` → arbitrary outside file. No path text appears anywhere in gift content, so no text gate can see it | A2's `isfile` follows the symlink; A3 sees nothing; `known_answer` reads the outside file, marks the entry "caught by R1…", returns exit 0 green, and the outside file's bytes are digested into `corpus_hash` (an offline content-confirmation oracle). With the mechanical count pins updated exactly as a normal PR would, the FULL suite is **60/60 OK** | **SMUGGLE (scoped-root escape + content oracle via contribution path)** |
| C2 | **Hostile typed negative**: runnable command-execution payload (`fn = getattr(os, "sys" + "tem"); fn(cmd)`), labeled `pass` / `typed_negative_for: R2-EVAL-FAMILY` — "a benign negative that is actually an attack the checker learns to ignore" | No gate inspects negative-fixture CONTENT. First attempt tripped R1/R2 via its own comment text (detector works); comment cleaned → entry reports "clean". With pins updated, full suite **60/60 OK**. The corpus now certifies a real attack shape as a benign lookalike, and the checker's line-based rules cannot fire on it (E8d) | **SMUGGLE (mislabelled attack through all gates)** |
| C3a | `fixture` set to a non-string (12345) | Unhandled `TypeError` crash of known_answer (engine trusts corpus.json blindly). The A2 gate would TypeError too, so a PR cannot merge it | NOTE (robustness; gate catches) |
| C3b | Crafted class id with `\n` + ANSI (`C1\x1b[31M-SHELL\nNEW-LINE-FORGED`); unknown label `detect-everything-is-fine` | Unknown label → receipt `all_pass: False` (handled, exit 2). Injected class id IS echoed into the receipt (`results[].class`) and the service `constable.corpus` tool — JSON-escaped, so no structural break, but attacker metadata rides into reports | NOTE |
| C4 | FIFO planted in the corpus directory (any filename) | `corpus_hash` opens every file under corpus/ with no type check → `known_answer` hangs forever (exit 124, timeout-kill). Contributor-reachable and also reachable by anyone who can write into a scanned tree | **SMUGGLE (hang)** |
| — | Duplicate fixture_id, missing caught_by, label outside vocabulary, fixture missing, MATRIX row missing | A2 test fails the build on each | Gates work as advertised |

### Server input path (booted scratch copy, 127.0.0.1:4902)

| # | Attempt | Actual result | Verdict |
|---|---|---|---|
| S1a | Duplicate `method` JSON keys (`status` then `scan`) | Last-key-wins (standard json.loads); no parser confusion beyond spec | RESISTED |
| S1b | Unicode-escaped tool name (`"\u0063onstable\u002escan"`) | Decodes to the canonical name; behaves identically | RESISTED |
| S1c–f | Unknown top-level field; params as string; paths as string; NUL in method name | 400 with precise errors; NUL echoed JSON-escaped (`constable\u0000.scan`) | RESISTED |
| S2 | Content-Length lies: negative → 400+close; huge → 413+close; non-numeric → 400; `+2` quirk → parsed as 2, harmless; short/absent → thread waits then 408 at exactly 30.0 s (documented timeout); zero → 400; exact boundary 65537 → 413, 65536 → parsed | All as designed, every error carries `Connection: close` | RESISTED |
| S3 | Path param attacks: control chars → 400; lone surrogate `\ud800` → 400 with JSON-escaped echo; relative path → 400 absolute-only; dot-segment absolute path → honest `os.path.exists` result (my probe path was itself wrong; server answered correctly) | No traversal past `isabs`+`exists`; no CRLF into headers (errors are body-only, JSON-encoded) | RESISTED |
| S4 | 50 000-deep nested body within the 64 KB cap | Clean 400 "body must be valid JSON"; no traceback in the service log. On this build (Python 3.14) json.loads raises JSONDecodeError (caught); on builds where it raises RecursionError the except-clause at server.py:212 would miss it → portability note, not a local break | RESISTED (portability note) |
| S5 | Arbitrary absolute-path scan from the service: a file planted in $HOME containing a fake API-key line plus an R1-matching line | 200 OK; returned path correctly home-redacted (`~/constable-a5b-secret.py`); ONLY the rule-matching line is excerpted (≤160 chars) — the unmatched fake-secret line was NOT echoed. The minimal-span law held. Structural fact: the service has no auth, so ANY local process can excerpt ≤160 chars of the rule-matching lines of ANY user-readable file, and can scan anywhere (PRD A7 words this as operator-scoped — the loopback caller IS the operator by this trust model). Flagged as hardening, not a smuggle under the documented model | NOTE (hardening) |
| S6 | Caps: 16 paths × dir scan OK (32 files); 33 paths → 400 | MAX_PATHS enforced | RESISTED |
| S7 | Service tools over the HOSTILE corpus (C1c/C2 installed) | `constable.known_answer` → 200, all_pass true, attacks 14 — the symlinked outside-file fixture served green through the shipped service surface; `constable.corpus` → 29 entries | Confirms C1c/C2 are reachable through the service, not just the CLI |
| S8 | Service log inspection after the whole battery | Zero tracebacks, zero scanned content in stderr; only `constable-service: "POST / HTTP/1.1" <code>` lines | A8 log redaction held |

## 2. Smuggles achieved (target: zero — NOT met)

1. **S-1 (text-report injection via filename) — engine.py --text writer,
   lines ~404–415.** A filename containing `\n` and ANSI escapes is written
   raw into the human-readable report; an attacker who can plant a file in
   any scanned tree forges arbitrary report lines (fake findings, fake
   "clean" verdicts) and injects terminal escape sequences. JSON mode is
   unaffected (escapes correctly). Repro: E1a output above
   (`/tmp/constable-attack/target/evil-dir`).
2. **S-2 (indefinite hang via non-regular files) — engine.py
   `_iter_target_files`/`scan_file` (open at line 212) and `corpus_hash`
   (open at line ~286).** A FIFO named `*.py` in any scanned directory hangs
   the scan forever (E5c, exit 124; reproduced through the live service —
   each such scan request pins a service thread forever). A FIFO anywhere
   under corpus/ hangs `known_answer` forever (C4). A symlink loop named
   `*.py` crashes the run with an unhandled OSError instead of a report (E6).
3. **S-3 (scoped-root escape + content oracle through the contribution
   path) — engine.py `known_answer` line 315
   (`os.path.join(fixtures_dir, rel)` with no containment) and
   tests/test_corpus_integrity.py line 73 (same unchecked join).** A corpus
   entry whose `fixture` field is a symlink (no text footprint → A3-blind;
   A2's isfile follows it) makes the operator's known-answer run read an
   arbitrary operator-readable file outside corpus/fixtures, evaluate a
   label against it (an attacker-readable boolean oracle), and digest its
   bytes into `corpus_hash`. Absolute `/tmp/...` fixture paths also pass the
   A3 text gate outright (C1b). Repro: `/tmp/constable-attack/build`, hostile
   PR v2, full suite 60/60 OK.
4. **S-4 (runnable attack certified as a benign typed negative through all
   gates) — gap is in the gate set: no gate inspects negative/defense
   fixture CONTENT.** `getattr(os, "sys" + "tem")` followed by `fn(cmd)` —
   real command execution, invisible to every line-based rule (E8d) — merged
   as a `pass` entry with `typed_negative_for`, suite 60/60 OK. The corpus
   then teaches downstream consumers that this shape is safe, and A4's
   known-answer certifies it as "clean". Repro:
   `corpus/fixtures/negatives/neg-r2-getattr-build.py` in the scratch copy.

No smuggle achieved: code execution / interpretation inside the engine
(execution surface verified clean independently); JSON-structure break in any
output (all JSON paths escape correctly); content echo beyond the 160-char
minimal span (A8 held at runtime, modulo the E9 tiny-file letter-edge); any
escape of the service's request parsing (all probes bounded and answered).

## 3. Required fixes (precise; not applied — adjudicator does not fix)

1. **engine.py, `scan_file` (~line 208–216) and `corpus_hash` (~line
   281–291):** before every `open()`, stat the path and require
   `stat.S_ISREG` (skips FIFOs, devices, and — with `os.path.realpath`
   containment below — symlink escapes); wrap stat+open+read in
   `try/except OSError: return []` / `continue` so hostile trees degrade to
   skipped files, never hangs or tracebacks. Fixes S-2 and E6.
2. **engine.py, `known_answer` (line ~314–315) and
   tests/test_corpus_integrity.py (line ~73):** require `entry["fixture"]`
   to be a `str` with no `..` segment and no leading `/`, then resolve and
   enforce containment:
   `abs = os.path.realpath(os.path.join(fixtures_dir, rel))` must be under
   `os.path.realpath(fixtures_dir) + os.sep`. Add the same check to the A2
   gate so a hostile PR fails pre-merge. Fixes S-3 (C1a/b/c).
3. **engine.py, `--text` writer (lines ~404–415):** escape non-printables in
   `f["path"]` (and defensively in excerpts) before stdout, e.g. replace
   chars with `ord < 0x20 or ord == 0x7f` by `\uXXXX`; or emit the text
   report from the same escaped strings JSON uses. Fixes S-1 (E1a).
4. **Contribution gates (new mechanical check in tests/, e.g. extending
   test_corpus_integrity.py):** for every entry labeled `pass`/`reject`,
   scan the fixture's NORMALIZED form — at minimum lenient-decode, drop NULs,
   and also scan a whitespace-joined variant of the text (defeats
   cross-line splits) plus a `getattr(`-with-string-concatenation
   heuristic — and fail the build if any rule fires on the normalized form.
   Pair with a README rule-of-engagement line that typed negatives are
   human-reviewed. Closes the S-4 channel mechanically to the extent a
   pattern gate can; documents the residual (evasion is undecidable in
   general — say so in the README's known-limits note).
5. **Non-blocking hardening (recommend, not gate-fail):** (a) server.py —
   add `RecursionError` to the json parse except-clause (server.py:212) for
   portability; (b) document on the service surface that any local process
   can scan any user-readable path (or add a `CONSTABLE_ROOTS` allowlist
   env, defaulting to open for CLI parity); (c) A8 letter-edge: either bound
   excerpts to < full tiny-file content or amend the redaction law's wording
   to "never more than 160 characters" (E9).

## 4. Adjudicator verdict

**A5b: FAIL.** Target was zero smuggles; four were achieved (S-1 text-report
injection, S-2 indefinite hang, S-3 contribution-path scoped-root escape with
content oracle, S-4 runnable attack certified as a typed negative), plus one
crash finding (E6) folded into S-2's fix. The execution-surface prohibitions
(A5a) and the server's request parsing survived everything thrown at them —
the failures are all at the engine's filesystem input boundary, the text
output boundary, and the contribution trust boundary. Blocking list = fixes
1–4 above; fix 5 recommended. Re-run of this A5b pass (same battery, all four
fixes in place) is the acceptance condition for the gate.

# Constable — the injection-defense kit (Drop 3 gift)

Receipt (pinned verbatim by tests/test_docs_pins.py — if it drifts, the
build fails):

This kit teaches a defense discipline and ships a reference checker. It claims nothing about the security of any deployed ResonantOS system. All corpus entries are public attack classes demonstrated on synthetic fixtures. This is not a security audit.

Constable is the defense half of the discipline behind the merged
quote-aware-argv fix (PR 333, commit `72c649f`), handed to the add-on authors
the SDK moment creates. One repo, three deliverables that work as one
instrument:

1. **The doctrine** — `docs/DOCTRINE.md`: injection by construction, ported
   to the browser-first alpha (MV3 extension + authenticated loopback bridge
   + SDK add-on surface), four stored-content patterns with their
   data-boundary alternatives, worked examples citing only merged fixes and
   our own origin bugs.
2. **The corpus** — `corpus/`: a known-answer fixture set of public attack
   classes on synthetic fixtures, each entry carrying a class id, a public
   citation (CWE or equivalent), an expected-outcome label, and typed
   negatives; coverage matrix in `corpus/MATRIX.md`.
3. **The checker** — `engine.py` (CLI) + `server.py` (loopback local service,
   127.0.0.1:4902) + `addon.json`: stdlib-only, detect-and-explain,
   deterministic. Its own prohibition is test-pinned: no subprocess, no
   dynamic evaluation, literal-regex-only patterns, fixtures read as opaque
   bytes.

This sits inside the community's own defense tradition — PR 333, ADR-034,
and the security pipeline — as a teaching companion for add-on authors, and
in its own fixture philosophy: a fixture is a crash-test dummy for the
evidence pipeline. It is not a replacement for the project's security
pipeline and is not wired into any CI.

## Quick start

```sh
# scan a tree you own (operator-scoped; detect-and-explain, never fails)
python3 engine.py path/to/your/addon

# human-readable report
python3 engine.py path/to/your/addon --text

# known answer against the pinned corpus
python3 engine.py --known-answer

# or run the service (binds 127.0.0.1:4902 only)
python3 server.py
curl -s http://127.0.0.1:4902/health
```

Tools on the service: `constable.status`, `constable.scan` (1..16 absolute
paths you choose), `constable.corpus`, `constable.known_answer`.

## Rules of engagement — the contest

The contest is the corpus itself, shaped as a defense rehearsal: extend the
known-answer corpus and the coverage matrix, and the checker re-runs. There
are no live targets, no winners, no prizes, and no bounty mechanics — this
is never aimed at any deployed system, and it is not a hacking challenge.
Submissions arrive as ordinary PRs to OUR repo, and every one passes the
same gates the shipped corpus passed.

**Contribution gates (applied to every incoming fixture or pattern PR before
merge):**

- **A2 — integrity:** every entry must carry a class id, a public-class
  citation, a synthetic fixture, an expected-outcome label, and a typed
  negative where applicable (the deterministic applicability rule is stated
  in `corpus/README.md`); `tests/test_corpus_integrity.py` fails the build
  on any missing field — and a fixture that does not exist fails the
  engine's own known-answer run too, never a phantom "clean" negative.
  Fixture paths are strictly contained — a `fixture` value must be a clean
  path relative to `corpus/fixtures`: `..` traversal, absolute paths, and
  symlinks escaping the fixtures root each fail the build with a named
  reason. For `pass`/`reject` fixtures there is also a MECHANICAL content
  gate: the fixture text is scanned in normalized form (exact,
  whitespace-joined — defeating cross-line splits — and unicode-unescaped,
  decoding JS `\uXXXX` escapes and `String.fromCharCode(...)`) for
  runnable execution construction — `getattr(...)`/`eval(...)`/`exec(...)`
  /`compile(...)` dynamic evaluation, dynamic module import, `os.system`/
  `os.popen` tokens in ANY shape (call or alias-then-call, paren not
  required), the `os.posix_spawn`/`exec`/`spawn` family, bare `Function(...)`
  and `new Function`, the `child_process` exec/spawn shell-string family
  (`execSync` in any shape), dynamic-index execution over the global object
  (`globalThis[...]`), dynamic dispatch by string-literal name
  (`obj["eval"](...)`), and string-literal + string-literal assembly of
  execution names (`getattr(os, "sys" + "tem")` is the canonical smuggle).
  A hit fails the build. This gate is a heuristic, not a decision
  procedure — general evasion is undecidable (runtime-encoded names such as
  atob/base64 decode, or constructor indirection, can still slip it) — so
  every typed negative is additionally HUMAN-REVIEWED before merge: a
  negative fixture that can execute anything is refused regardless of its
  label. The human review layer, not the mechanical gate, is what
  certifies a negative benign.
- **A3 — synthetic-only, mechanized:** an automated scan proves the corpus
  contains zero paths, hostnames, domains, or token-shaped literals drawn
  from any live deployment — normalized path-segment and domain-suffix
  comparison against the committed `ALLOWLIST`, a high-entropy token scan,
  and a citation allowlist that the grep gate reads. Anything cited outside
  the allowlist fails the build (`tests/test_a3_synthetic_scan.py`).
- **A5a — literal-regex-only contributed patterns:** new detection patterns
  ship as code PRs whose regexes are literals compiled at load — a
  contributor shipping a catastrophic-backtracking pattern must not be able
  to self-DoS the checker. The same grep/AST gate that guards the engine
  (`tests/test_a5a_engine_gate.py`) runs on every PR.

The golden end-to-end example — add a pattern + fixture + expected outcome,
update the matrix, and watch the checker go green — is executable:
`tests/test_golden_extension.py`.

## What known-answer proves (read this before citing numbers)

Because corpus and checker are co-developed, the known-answer run proves the
checker executes its own labels — it is NOT an efficacy claim against the
world. (This sentence is pinned by the same docs test as the banner.)

## Governance

- Corpus attacks are known/public classes demonstrated against synthetic
  fixtures only; no live-exploit material, no weaponized chains, nothing
  derived from any private report or any unfixed site.
- Worked examples cite only merged fixes (PR 333, ADR-034) and public docs;
  the citation allowlist (`ALLOWLIST`) is enforced by the build gate.
- The checker requests filesystem access only, reads only the paths its
  operator passes, dials nothing, and persists nothing beyond its own
  `var/` reports; scanned contents are never echoed whole (findings quote
  minimal spans), and home paths are redacted on disk and in responses.
- Service surface, stated plainly: the local service is UNAUTHENTICATED by
  design and binds 127.0.0.1:4902 only — it is reachable only by processes
  on the same machine, and in this trust model the loopback caller IS the
  operator. That means any local process can ask it to scan any
  user-readable absolute path (findings quote at most 160 characters of the
  matching lines). Run it only on hosts whose local users you trust; it
  never dials out and never binds a wider interface, and startup fails loud
  (exit 78) on any bind conflict.
- Vulnerabilities in ResonantOS itself belong in the project's SECURITY.md
  private lane, not here.

## Licenses

Code: MIT. Doctrine, README, corpus, and procedure docs: CC-BY-4.0
(see `LICENSE`). Creation trail: `PROVENANCE.md`; build-time record:
`PROCEDURE.md`.

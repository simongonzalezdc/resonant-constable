# DOCTRINE — injection by construction, ported to the browser-first alpha

Part of the Constable gift (`addon.constable`). Code is MIT; this document is
CC-BY-4.0. Provenance for every claim is inline.

## The law

> **Stored content is never interpolated into shell strings; parse as data;
> adversarial QA is the gate that catches what review misses.**

Our canonical injection-by-construction law, carried as hard law #4 in
PROJECT-DOSSIER.md (augmentatism-stack). Lineage: born in the
augmentatism-stack sessions of 2026-08-30/31, where adversarial QA caught the
same bug class twice in one night — both bugs had survived code review:

1. **`bin/cure`** — a newline inside a parked request forged a `cutoff:` field
   that won a first-match parse. The parser trusted keyword position, not a
   field grammar. (Origin bug, ours, 2026-08-30.)
2. **`bin/authority`** — `--source 'x$(cmd)y'` was executed via awk's
   `system()` on every later query. Stored text became a shell command per
   row. (Origin bug, ours, 2026-08-30.)

Structure-based parsing — block scalars, membership files, fixed grammars —
has no injection surface: there is no position in the program where stored
bytes are interpreted as syntax.

## We are not teaching them their own tradition — we are handing it back

This gift sits inside THEIR defense tradition, and credits it first:

- **PR 333** (merged 2026-08-31 by tompennington, commit `72c649f`:
  "security(engineer-runner): quote-aware argv execution, no shell"): the
  exact class this kit teaches, fixed in their tree — commands tokenize with
  a minimal quote-aware splitter, execution is argv with no shell, and
  unquoted metacharacters, empty commands, and unterminated quotes are
  refused (validate-and-refuse). The fix is the template for Pattern 2 below.
- **ADR-034** ("Engineer Runner Guardrails", accepted 2026-05-13): required
  commands are executed by the runner, not trusted from model output, and
  scope violations fail deterministically. The ADR's principle — never trust
  model-produced content at an execution boundary — is the same principle
  this doctrine applies to stored content at every boundary.
- **Their security pipeline** (`node scripts/security-pipeline/run-check.mjs`
  for security-sensitive paths, per their AGENTS.md): this kit is a
  teaching companion to that pipeline for add-on authors. It is never a
  replacement for it and is not wired into their CI.
- **Their fixture philosophy** (economy-research): "a fixture is like a
  crash-test dummy for the evidence pipeline" — the corpus is built in
  exactly that image: labeled dummies, known answers, typed negatives.

**Taxonomy provenance clause:** the class taxonomy and priority ordering in
this document derive ONLY from public history — our own two origin bugs, the
merged PR 333 class, and public CWE/OWASP families. Nothing here is derived
from the existence, absence, or timing of any private report, and no unfixed
site in any tree is referenced, alluded to, or shaped around.

## Their surface, their words

The audience is the add-on authors their SDK moment creates. Their own
SECURITY.md names the surface in scope (quoted verbatim from "Supported
Security Boundary"):

> "provider routing, subprocess invocation, and process environment handling"
>
> "add-on manifests, capability grants, allowed-tools declarations, and
> scoped bridge APIs"

An add-on holds stored content (notes, archives, tool output) and often
spawns processes or builds prompts. That is precisely the geometry where the
four patterns below live. Reports for anything else go down their SECURITY.md
private lane — this kit does new-findings triage nowhere.

---

## Pattern 1 — stored content crossing a message boundary (P1-message-boundary)

**The shape.** Stored content (a note, a tool result, an archive row) is
concatenated into instruction-bearing text — a prompt, a delegation brief, a
bridge message that another component will parse for directives. The boundary
between operator intent and stored data is one the data can rewrite.

**Public class.** OWASP Top 10 for LLM Applications, LLM01: Prompt Injection
(https://owasp.org/www-project-top-10-for-large-language-model-applications/).

**In their architecture.** The MV3 side panel and background worker pass
stored page content across the extension message boundary; the authenticated
loopback bridge forwards briefs to agents. Any place a template says
`"Instructions: ..." + storedNotes` is this pattern.

**The data-boundary alternative.** Carry stored content across a structured,
fenced boundary the receiving grammar defines: labeled sections joined as
data (`[HEADER, "<stored-notes>", notes, "</stored-notes>"].join("\n")`), or
structured message fields. The receiver consumes the fence grammar; stored
bytes never become syntax. Never concatenate into instruction text.

**Corpus binding.** Class C5, fixtures F-PROMPT-001/002, typed negatives
N-PROMPT-001/002; checker rule R5-INSTRUCTION-CONCAT.

## Pattern 2 — stored content reaching a subprocess argv or a shell string (P2-shell-string)

**The shape.** A command string is assembled by interpolation from stored
fields and handed to a shell — or stored text is handed to a dynamic
evaluator, which is the same crime with a different parser.

**Public class.** CWE-78: OS Command Injection
(https://cwe.mitre.org/data/definitions/78.html); CWE-95: Eval Injection
(https://cwe.mitre.org/data/definitions/95.html).

**Worked example (merged fix, public).** Their engineer-runner executed
contract commands through a shell: the pre-merge runner spawned the command
string with a shell. PR 333 (commit `72c649f`, merged 2026-08-31) fixed the
site the doctrine way:

- a minimal quote-aware splitter groups quoted segments into literal argv words;
- execution runs argv with no shell, so nothing is ever interpolated;
- unquoted shell metacharacters, empty commands, and unterminated quotes are
  REFUSED with an explanatory error (validate-and-refuse — stricter than the
  runtime remedy, and correct for a dev-time gate).

(Worked example: ADR-034 adds the governance half — required commands are
executed by the runner, never trusted from model output.)

**Origin example (ours).** `bin/authority` (2026-08-30): stored `--source`
values reached awk's `system()` and executed on every later query. The fix
shape was the same in kind: stop evaluating stored text; parse it as data
against a membership file.

**The data-boundary alternative.** Kill the string: argv arrays with no
shell; quote-aware splitting with validate-and-refuse where humans write
commands; fixed dispatch tables instead of dynamic evaluation. awk `system()`
per row is a shell string by another name — replace with fixed-grammar
parsing and membership checks.

**Corpus binding.** Classes C1 and C2, fixtures F-SHELL-001/002 and
F-EVAL-001/002/003, typed negatives N-SHELL-001/002 and N-EVAL-001/002,
defense exemplar D-SHELL-001; checker rules R1 and R2.

## Pattern 3 — stored content parsed by first-match or loose grammars (P3-loose-grammar)

**The shape.** A parser locates a bare keyword and takes whatever follows:
`text.split("cutoff")[1]`, `body.indexOf("token") + 5`. First match wins, so
a forged keyword inside stored content wins the parse.

**Public class.** CWE-20: Improper Input Validation
(https://cwe.mitre.org/data/definitions/20.html) — the validation is
positional, not grammatical.

**Origin example (ours, the canonical one).** `bin/cure` (2026-08-30): a
newline inside a parked request forged a `cutoff:` field that won the
first-match parse and re-ordered the queue. Code review had passed it;
the adversarial-QA pass caught it. The remedy is structural: full field
delimiters (`"key: "`), a closed field vocabulary, typed values, and refusal
of anything that does not match — a fixed grammar has no "whatever follows."

**In their architecture.** Parked requests, keyed status files, bridge
messages parsed by prefix search — any `indexOf`/`split(keyword)` reader of
stored bytes.

**The data-boundary alternative.** Parse as data: full delimiters, closed
vocabularies, fixed grammars, refuse on anything else (see the defense
exemplar D-PARSE-001 in the corpus).

**Corpus binding.** Class C3, fixtures F-PARSE-001/002, typed negatives
N-PARSE-001/002, defense exemplar D-PARSE-001; checker rule R3.

## Pattern 4 — stored text interpolated into regexes or query grammars (P4-regex-interpolation)

**The shape.** A pattern is assembled from stored text:
`re.compile(f"^user:{name}")`, `new RegExp(storedPrefix)`. Metacharacters in
the data rewrite the grammar; and a quantified-group-within-quantified-group
pattern (CWE-1333) turns adversarial input into exponential backtracking —
a denial of service in one line.

**Public class.** CWE-185: Incorrect Regular Expression
(https://cwe.mitre.org/data/definitions/185.html); CWE-1333: Inefficient
Regular Expression Complexity
(https://cwe.mitre.org/data/definitions/1333.html).

**The data-boundary alternative.** Pre-built literal patterns only; if the
key must vary, escape it with a quoting function or refuse non-conforming
keys before they reach the grammar. This is also self-defense for checkers:
the Constable contribution gates (README, rules of engagement) require
literal-regex-only contributed patterns precisely so a contributor cannot
hand the checker a catastrophic pattern and self-DoS it. The checker's own
rules are literal regexes compiled once at load (A5a).

**Corpus binding.** Classes C4 and C6, fixtures F-REGEX-001/002 and
F-REDOS-001/002, typed negatives N-REGEX-001/002 and N-REDOS-001/002;
checker rules R4 and R6.

---

## How to run the rehearsal

1. Read this doctrine; pick the pattern that matches your add-on's boundary.
2. Run the checker over your tree: `python3 engine.py path/to/your/addon`
   (or serve it: `python3 server.py`, then POST `constable.scan` to
   127.0.0.1:4902). Default is detect-and-explain — it never fails your build.
3. Read the corpus (`corpus/corpus.json`, `corpus/MATRIX.md`) and the typed
   negatives: each one is a benign construct a defense must not flag.
4. When you add a fixture or pattern, the contribution gates in the README
   apply (A2 integrity, A3 synthetic-only, A5a literal-regex-only) — the
   golden end-to-end example is `tests/test_golden_extension.py`.

## Scope and claims

This kit teaches a defense discipline and ships a reference checker. It
claims nothing about the security of any deployed ResonantOS system. All
corpus entries are public attack classes demonstrated on synthetic fixtures.
This is not a security audit. New findings made incidental to using it go
down their SECURITY.md private lane and nowhere else.

# PROVENANCE — creation trail (A10)

Created 2026-09-02, by the Kyanite Labs gift pipeline (resonant-gift-wrap),
on the CEO-approved build order for Drop 3 "Constable", after the consensus
gate (architect approve-with-notes, critic approve). Publication is a
separate gated step; this build is local-only.

## Originality

- ALL code in this gift (engine.py, server.py, tests, the argv-refuser and
  strict-field defense exemplars) is original, written for this gift. ZERO
  code was copied from any external repository, including the ResonantOS
  2.0.0-alpha tree. The defense exemplar D-SHELL-001 is an original
  synthetic shape written to demonstrate the pattern the merged PR 333 fix
  applied; it is not their code.
- The doctrine (docs/DOCTRINE.md) is original text; the canonical law
  sentence ("stored content is never interpolated into shell strings; parse
  as data; adversarial QA is the gate that catches what review misses") is
  our own law from PROJECT-DOSSIER.md (augmentatism-stack), quoted as
  canon. The two origin bugs cited (bin/cure, bin/authority,
  augmentatism-stack, 2026-08-30) are ours.
- All external citations are public: CWE entries, the OWASP LLM Top 10,
  their merged PR 333 (commit 72c649f, subject "security(engineer-runner):
  quote-aware argv execution, no shell"), their ADR-034, their public
  SECURITY.md boundary lines, and their public security-pipeline doc
  reference. No unfixed site is cited, alluded to, or shaped around
  anywhere in this gift.
- All fixtures are synthetic: no real names, hosts, domains, credentials,
  or tokens; sample data uses /tmp paths and example-shaped values only.

## Local-service lineage (pattern credit)

The hardened service shape (per-method param allowlists, body caps,
408/413 with Connection: close, bind-conflict exit 78, home-path redaction
on disk and responses) follows the established sibling local-service
pattern (stack-bench, innerscape, addon.a2a-bridge, evidence-fixtures,
context-kit), which itself follows the ResonantOS add-on contract. The
Connection: close advertisement on error replies follows the
resonant-context-kit fix (server.py, master).

## License

Code MIT (Kyanite Labs); doctrine/README/corpus/procedure docs CC-BY-4.0
(see LICENSE). A10 licensing law: code MIT, doctrine CC-BY.

## Verification trail (build-time, recorded in the build report)

Validator against the real 2.0.0-alpha validator (dev pinned), suite green
twice, A3 synthetic-only mechanized scan, A5a engine gate, known-answer
100% on the pinned corpus, determinism sha256 + 4-parallel, live
adversarial matrix on 127.0.0.1:4902, A9 golden extension end-to-end.
A5b (fresh-adversary) is declared in PROCEDURE.md with the adjudicator
TBD at the build gate.

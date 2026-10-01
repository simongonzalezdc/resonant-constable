# The Constable corpus

A known-answer fixture set of KNOWN, public injection attack classes,
demonstrated on synthetic fixtures only — crash-test dummies for the
evidence-adjacent code add-on authors write, not exploits. Every fixture is
original and synthetic: no real names, hosts, credentials, or code copied
from any repository.

## Entry format

`corpus.json` is the index of record. Every entry carries:

- `fixture_id` — stable id (`F-*` attack, `N-*` typed negative, `D-*` defense exemplar);
- `class` — attack-class id, defined in `classes` with a public citation
  (CWE or an equivalent public reference such as the OWASP LLM Top 10);
- `fixture` — the synthetic fixture file, relative to `fixtures/`;
- `label` — the expected outcome: `detect` (checker must flag, at least via
  `caught_by`), `pass` (benign; checker must stay silent), or `reject`
  (the fixture IS a data-boundary defense that refuses the input; checker
  must stay silent);
- and, by label: `caught_by` (rule id) for `detect`, `typed_negative_for`
  (rule id) for `pass`, `defense_of` (rule id) for `reject`.

## Typed-negative applicability rule (deterministic)

Every **defense pattern** (engine rule R1–R6) carries at least one typed
negative. Attack-class entries carry typed negatives wherever a benign
lookalike exists; in this corpus every class has at least one lookalike, so
every class carries at least one typed negative. The integrity test
(`tests/test_corpus_integrity.py`) enforces exactly:

1. `label == "pass"` implies a `typed_negative_for` naming a known rule;
2. every rule id has at least one typed negative;
3. every class id has at least one typed negative.

A defense must never flag a benign construct; each negative names the rule
it must not trigger.

## Known answer

`python3 engine.py --known-answer` runs every entry against its label and
reports 100% or names the drift. Because corpus and checker are co-developed,
the known-answer run proves the checker executes its own labels — it is not
an efficacy claim against the world.

## Extending the corpus (the contest)

Fixtures arrive as ordinary PRs to OUR repo. Every incoming fixture PR passes
the same three gates before merge: A2 (integrity), A3 (synthetic-only,
mechanized), and A5a (literal-regex-only contributed patterns). See the
README's rules of engagement, and the golden end-to-end example in
`tests/test_golden_extension.py`.

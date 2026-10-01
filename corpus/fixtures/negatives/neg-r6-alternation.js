// N-REDOS-002 — typed negative for R6-CATASTROPHIC-QUANTIFIER
// (class C6-REDOS-BACKTRACKING). Benign lookalike: no nested quantifier.
// Expected label: pass.

const KEY_SHAPE = new RegExp("^(?:cat|dog)+$");

function isKey(line) {
  return KEY_SHAPE.test(line);
}

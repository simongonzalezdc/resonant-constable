// F-REDOS-002 — synthetic attack fixture, class C6-REDOS-BACKTRACKING
// (CWE-1333). Nested quantifiers in a constructed pattern. Expected label:
// detect (R6-CATASTROPHIC-QUANTIFIER).

const KEY_SHAPE = new RegExp("(\\w+)*$");

function isKey(line) {
  return KEY_SHAPE.test(line);
}

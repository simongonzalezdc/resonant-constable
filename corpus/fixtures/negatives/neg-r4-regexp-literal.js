// N-REGEX-002 — typed negative for R4-REGEX-INTERPOLATION
// (class C4-REGEX-INTERP). Benign lookalike: the pattern is a literal, the
// subject is the variable. Expected label: pass.

const USER_SHAPE = new RegExp("^user:[a-z0-9_]{1,64}$", "i");

function isUser(line) {
  return USER_SHAPE.test(line);
}

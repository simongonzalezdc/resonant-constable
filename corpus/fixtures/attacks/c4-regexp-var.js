// F-REGEX-002 — synthetic attack fixture, class C4-REGEX-INTERP (CWE-185).
// A stored prefix becomes the pattern itself. Expected label: detect
// (R4-REGEX-INTERPOLATION).

function matchStoredPrefix(prefix, line) {
  return new RegExp(prefix).test(line);
}

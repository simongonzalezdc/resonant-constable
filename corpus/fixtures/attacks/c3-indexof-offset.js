// F-PARSE-002 — synthetic attack fixture, class C3-LOOSE-PARSE (CWE-20).
// Bare keyword plus a fixed offset: no field boundary is validated, so any
// stored occurrence of the keyword re-anchors the parse. Expected label:
// detect (R3-LOOSE-KEY-PARSE).

function takeToken(body) {
  const at = body.indexOf("token") + 5;
  return body.slice(at);
}

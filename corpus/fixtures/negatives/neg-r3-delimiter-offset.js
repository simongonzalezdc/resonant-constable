// N-PARSE-002 — typed negative for R3-LOOSE-KEY-PARSE (class C3-LOOSE-PARSE).
// Benign lookalike: the needle includes the full "key: " separator and the
// offset is the marker's real length. Expected label: pass.

function takeToken(body) {
  const marker = "token: ";
  const at = body.indexOf(marker) + marker.length;
  return body.slice(at);
}

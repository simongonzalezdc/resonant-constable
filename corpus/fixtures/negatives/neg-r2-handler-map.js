// N-EVAL-002 — typed negative for R2-EVAL-FAMILY (class C2-EVAL-STORED).
// Benign lookalike: a handler map. Expected label: pass.

const handlers = { tag: tagRecord, note: noteRecord };

function dispatch(kind, record) {
  const fn = handlers[kind];
  return fn ? fn(record) : { refused: true };
}

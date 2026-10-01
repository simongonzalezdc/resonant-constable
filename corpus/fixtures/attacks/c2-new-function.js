// F-EVAL-002 — synthetic attack fixture, class C2-EVAL-STORED (CWE-95).
// A stored filter expression is compiled into a function: the data becomes a
// program. Expected label: detect (R2-EVAL-FAMILY).

function compileFilter(expr) {
  return new Function("item", "return filterItem(item, expr)");
}

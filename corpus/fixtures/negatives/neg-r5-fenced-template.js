// N-PROMPT-002 — typed negative for R5-INSTRUCTION-CONCAT
// (class C5-PROMPT-STORED). Benign lookalike: fenced sections joined, no
// concatenation into the instruction literal. Expected label: pass.

const HEADER = "Instructions: summarize the fenced notes.";

function brief(keptNotes) {
  return [HEADER, "<kept-notes>", keptNotes, "</kept-notes>"].join("\n");
}

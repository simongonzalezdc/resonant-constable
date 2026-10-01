// F-PROMPT-002 — synthetic attack fixture, class C5-PROMPT-STORED
// (OWASP LLM01). Raw concatenation across the instruction boundary.
// Expected label: detect (R5-INSTRUCTION-CONCAT).

function brief(keptNotes) {
  return "Instructions: summarize the notes below." + keptNotes;
}

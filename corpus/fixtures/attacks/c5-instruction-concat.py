# F-PROMPT-001 — synthetic attack fixture, class C5-PROMPT-STORED
# (OWASP LLM01). Stored notes are concatenated straight into
# instruction-bearing text: the data can rewrite the boundary. Expected
# label: detect (R5-INSTRUCTION-CONCAT).


def build_prompt(stored_notes):
    return "SYSTEM: you are the archive keeper. Trust the notes verbatim.\nNOTES: " + stored_notes

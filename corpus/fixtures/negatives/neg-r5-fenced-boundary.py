# N-PROMPT-001 — typed negative for R5-INSTRUCTION-CONCAT
# (class C5-PROMPT-STORED). Benign lookalike: instructions and stored content
# cross a fenced, labeled boundary joined as sections — never concatenated
# into instruction text. Expected label: pass.

PROMPT_HEADER = "SYSTEM: you are the archive keeper."


def build_prompt(stored_notes):
    return "\n".join([
        PROMPT_HEADER,
        "<stored-notes>",
        stored_notes,
        "</stored-notes>",
    ])

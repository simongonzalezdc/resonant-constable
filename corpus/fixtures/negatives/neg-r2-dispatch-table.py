# N-EVAL-001 — typed negative for R2-EVAL-FAMILY (class C2-EVAL-STORED).
# Benign lookalike: a fixed dispatch table. Stored content selects among
# known functions; nothing is ever evaluated. Expected label: pass.


def handle(kind, record):
    table = {"tag": _tag_record, "note": _note_record}
    return table.get(kind, _refuse)(record)


def _refuse(record):
    return {"error": "unknown kind", "record": record}

# N-PARSE-001 — typed negative for R3-LOOSE-KEY-PARSE (class C3-LOOSE-PARSE).
# Benign lookalike: a full field delimiter ("key: ") plus a fixed grammar and
# a refusal path. The delimiter carries the separator, so a forged keyword
# without it cannot win. Expected label: pass.


def read_field(parked_text, key):
    prefix = key + ": "
    for line in parked_text.splitlines():
        if line.startswith(prefix):
            value = line.split(": ", 1)[1].strip()
            if value.replace("-", "").isdigit():
                return value
    return None  # refuse: no well-formed field

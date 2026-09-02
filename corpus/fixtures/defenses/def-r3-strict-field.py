# D-PARSE-001 — defense exemplar (label: reject) for R3-LOOSE-KEY-PARSE
# (class C3-LOOSE-PARSE). A block-grammar field reader: full delimiters,
# a closed field vocabulary, typed values, refuse on anything else. The
# boundary refuses; the lint agrees. Expected label: reject (nothing fires).

FIELDS = ("cutoff", "owner", "state")


def read_record(parked_text):
    record = {}
    for line in parked_text.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(": ")
        if not sep or key not in FIELDS:
            return None  # refuse: no delimiter, unknown field, or forged key
        if not value.replace("-", "").isdigit():
            return None  # refuse: value outside the fixed grammar
        record[key] = int(value)
    return record

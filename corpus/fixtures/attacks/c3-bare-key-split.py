# F-PARSE-001 — synthetic attack fixture, class C3-LOOSE-PARSE (CWE-20).
# The first-match shape: a bare keyword is located and whatever follows is
# taken as the field, so a forged keyword inside stored content wins the
# parse. Expected label: detect (R3-LOOSE-KEY-PARSE).


def read_cutoff(parked_text):
    return parked_text.split("cutoff")[1].strip()

# F-EVAL-001 — synthetic attack fixture, class C2-EVAL-STORED (CWE-95).
# A stored rule (user content) is handed to a dynamic evaluator: the data
# becomes a program. Expected label: detect (R2-EVAL-FAMILY).


def apply_rule(source_rule, record):
    exec(source_rule)  # stored text becomes a program
    return record

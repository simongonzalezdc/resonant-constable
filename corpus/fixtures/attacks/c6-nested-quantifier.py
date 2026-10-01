# F-REDOS-001 — synthetic attack fixture, class C6-REDOS-BACKTRACKING
# (CWE-1333). Nested quantifiers: a quantified group inside a quantified
# group backtracks exponentially on adversarial keys. Expected label:
# detect (R6-CATASTROPHIC-QUANTIFIER).
import re

KEY_PATTERN = re.compile(r"^(a+)+$")


def valid_key(key):
    return bool(KEY_PATTERN.fullmatch(key))

# N-REDOS-001 — typed negative for R6-CATASTROPHIC-QUANTIFIER
# (class C6-REDOS-BACKTRACKING). Benign lookalike: one quantifier over a
# fixed alternation — linear. Expected label: pass.
import re

KEY_PATTERN = re.compile(r"^(?:ab)+$")


def valid_key(key):
    return bool(KEY_PATTERN.fullmatch(key))

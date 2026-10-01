# N-REGEX-001 — typed negative for R4-REGEX-INTERPOLATION
# (class C4-REGEX-INTERP). Benign lookalike: a literal pattern built once,
# no stored text inside. Expected label: pass.
import re

USER_KEY = re.compile(r"^user:[A-Za-z0-9_]{1,64}$")


def find_user(text):
    return USER_KEY.search(text)

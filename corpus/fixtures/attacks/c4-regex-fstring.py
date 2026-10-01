# F-REGEX-001 — synthetic attack fixture, class C4-REGEX-INTERP (CWE-185).
# A stored key is interpolated into a pattern: metacharacters in the key
# rewrite what the grammar matches. Expected label: detect
# (R4-REGEX-INTERPOLATION).
import re


def find_user_key(name, text):
    return re.compile(f"^user:{name}").search(text)

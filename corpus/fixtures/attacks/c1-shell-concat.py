# F-SHELL-001 — synthetic attack fixture, class C1-SHELL-INTERP (CWE-78).
# A stored note (user content) is concatenated into a command string: whatever
# the note contains, the shell parses as grammar. Expected label: detect
# (R1-SHELL-STRING-EXEC).
import os


def search_notes(query, store_path):
    return os.system("grep -e " + query + " " + store_path)

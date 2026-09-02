# N-SHELL-001 — typed negative for R1-SHELL-STRING-EXEC (class C1-SHELL-INTERP).
# Benign lookalike: an argv array with shell=False. The boundary parses
# arguments as data; nothing is interpolated into a command string.
# Expected label: pass (nothing fires).
import subprocess


def status():
    return subprocess.run(["git", "status", "--porcelain"], shell=False, check=False)

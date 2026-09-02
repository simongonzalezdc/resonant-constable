# D-SHELL-001 — defense exemplar (label: reject) for R1-SHELL-STRING-EXEC
# (class C1-SHELL-INTERP). A quote-aware argv splitter with
# validate-and-refuse: quoted segments group literal words, unquoted
# metacharacters and unterminated quotes are refused, and execution is argv
# with shell=False. Original synthetic shape written for this corpus, in the
# spirit of the merged fix described in docs/DOCTRINE.md — no code copied.
# The boundary refuses; the lint agrees. Expected label: reject (nothing
# fires).


def split_command(command):
    tokens, current, quote = [], "", None
    for ch in command:
        if quote:
            if ch == quote:
                quote = None
            else:
                current += ch
            continue
        if ch == '"' or ch == "'":
            quote = ch
            continue
        if ch.isspace():
            if current:
                tokens.append(current)
                current = ""
            continue
        current += ch
    if quote or not tokens:
        return None  # refuse: unterminated quote or empty command
    return tokens


def run_task(command):
    argv = split_command(command)
    if argv is None:
        return 126, "refused"
    import subprocess
    done = subprocess.run(argv, shell=False, check=False)
    return done.returncode, ""

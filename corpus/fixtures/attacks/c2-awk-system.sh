#!/bin/sh
# F-EVAL-003 — synthetic attack fixture, class C2-EVAL-STORED (CWE-95).
# The awk system() shape: every matching row's field is evaluated as a shell
# command, so a stored value like x$(reboot)y executes. Expected label:
# detect (R2-EVAL-FAMILY).
query="$1"
awk -v q="$query" '$0 ~ q { system("echo " $2) }' /tmp/authority.members

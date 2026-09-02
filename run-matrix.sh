#!/bin/sh
# Live adversarial matrix against the REAL service on 127.0.0.1:4902
# (the manifest port). Boots server.py as a real process, runs the probes,
# and leaves nothing behind. Exit 0 = matrix green.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=4902
LOG="$HERE/var/matrix-server.log"
mkdir -p "$HERE/var"

PYTHON="$(command -v python3)"
fails=0
pass() { echo "MATRIX PASS: $1"; }
fail() { echo "MATRIX FAIL: $1"; fails=$((fails + 1)); }

echo "== booting constable-service on 127.0.0.1:$PORT =="
"$PYTHON" "$HERE/server.py" >"$LOG" 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null' EXIT

up=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if "$PYTHON" - <<EOF
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", $PORT), timeout=1)
    s.close()
except OSError:
    sys.exit(1)
sys.exit(0)
EOF
  then up=1; break; fi
  sleep 0.5
done
[ "$up" = 1 ] || { fail "service did not come up (see var/matrix-server.log)"; exit 1; }
pass "service up on 127.0.0.1:$PORT"

"$PYTHON" - <<'EOF'
import json, os, socket, sys, threading, urllib.error, urllib.request

PORT = 4902
fails = []

def note(ok, name):
    print(("MATRIX PASS: " if ok else "MATRIX FAIL: ") + name)
    if not ok:
        fails.append(name)

def raw(payload, timeout=10):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    try:
        s.sendall(payload)
        try:
            return s.recv(65536)
        except (ConnectionResetError, BrokenPipeError):
            return b""
    finally:
        s.close()

# 1. oversized body -> 413 + Connection: close advertised
big = json.dumps({"method": "constable.status", "pad": "x" * 100000}).encode()
data = raw(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(big)).encode() +
           b"\r\n\r\n" + big[:65537])
note(data.startswith(b"HTTP/1.1 413") and b"Connection: close" in data,
     "oversized body -> 413 + Connection: close advertised")

# 2. lying Content-Length -> 408 + close (production handler timeout is 30s:
# this live probe waits it out on the REAL path — no test-time patching)
data = raw(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n" +
           b'{"method":"constable.stat', timeout=40)
note(data.startswith(b"HTTP/1.1 408") and b"Connection: close" in data,
     "lying Content-Length -> 408 + Connection: close")

# 3. chunked -> 400 (no Content-Length to trust)
data = raw(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"1a\r\n{\"method\":\"constable.status\"}\r\n0\r\n\r\n")
note(data.startswith(b"HTTP/1.1 400"), "chunked encoding -> 400")

# 4. control chars in a param -> 400
def post(payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode()

try:
    post({"method": "constable.scan", "params": {"paths": ["/tmp/a\x01b"]}})
    note(False, "control chars -> 400")
except urllib.error.HTTPError as exc:
    with exc:
        note(exc.code == 400, "control chars -> 400")

# 5. unknown tool -> 400
try:
    post({"method": "constable.unknown"})
    note(False, "unknown tool -> 400")
except urllib.error.HTTPError as exc:
    with exc:
        note(exc.code == 400, "unknown tool -> 400")

# 6. 20-request concurrent flood -> all 200
errors = []
def hit(n):
    try:
        code, body = post({"method": "constable.status"})
        if code != 200:
            errors.append((n, code))
    except Exception as exc:
        errors.append((n, repr(exc)))
threads = [threading.Thread(target=hit, args=(i,)) for i in range(20)]
for t in threads: t.start()
for t in threads: t.join(timeout=30)
note(not errors, "20-request concurrent flood -> all 200")

# 7. privacy: scan a file carrying a home path; no home path in any output
home = os.path.expanduser("~")
victim = "/tmp/constable-matrix-leaky.py"
with open(victim, "w") as f:
    f.write("value = eval(payload)  # " + home + "/private/things\n")
code, bodytext = post({"method": "constable.scan", "params": {"paths": [victim]}})
ok = code == 200 and home not in bodytext and "~/private/things" in bodytext
note(ok, "privacy scan: no home path in scan output, redaction present")

# 8. privacy: real round-trip status carries the receipt banner
code, bodytext = post({"method": "constable.status"})
banner = json.loads(bodytext)["banner"]
note(banner.startswith("This kit teaches a defense discipline"),
     "real round-trip: receipt banner on status")

if fails:
    sys.exit(1)
EOF
[ $? -eq 0 ] || fails=$((fails + 1))

# 9. bind conflict -> exit 78 (second instance while the first holds 4902)
"$PYTHON" "$HERE/server.py" >/dev/null 2>&1
rc=$?
[ "$rc" -eq 78 ] && pass "bind conflict -> exit 78" || fail "bind conflict exit was $rc (want 78)"

# 10. privacy tree scan: no home-path byte string anywhere in the gift tree
# (needle built at runtime so this script itself stays clean)
if HERE="$HERE" "$PYTHON" - <<'EOF'
import os, sys
needle = (os.sep + "Users" + os.sep).encode()
bad = []
for dirpath, dirs, names in os.walk(os.environ["HERE"]):
    dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
    for name in names:
        if name.endswith(".pyc"):
            continue
        p = os.path.join(dirpath, name)
        with open(p, "rb") as f:
            if needle in f.read():
                bad.append(p)
for p in bad:
    print("privacy leak:", p)
sys.exit(1 if bad else 0)
EOF
then pass "privacy tree scan: no home paths anywhere in the gift"; else fail "privacy tree scan found home paths"; fi

echo "== matrix summary =="
[ "$fails" -eq 0 ] && echo "MATRIX GREEN (10/10 checks)" || echo "MATRIX RED ($fails failing)"
exit "$fails"

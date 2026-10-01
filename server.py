#!/usr/bin/env python3
"""addon.constable local-service entry (http-json on 127.0.0.1:4902).

ResonantOS add-on contract: protocol http-json, healthCommand constable.status.
Wraps the stdlib-only injection-defense checker (engine.py) in-process: no
subprocess, no secrets, no outbound network. Reads are operator-scoped — the
scan tool touches only the paths the operator passes in the request; there is
no discovery beyond them.

Hardening (sibling local-service pattern, tested):
  - per-method param allowlists (never a union); unknown field -> 400;
  - control characters rejected in identifier params -> 400;
  - body <= 64KB (413 + Connection: close), lying Content-Length -> 408 +
    close, chunked encoding -> 400 (no Content-Length to trust);
  - every error reply advertises Connection: close and actually closes;
  - non-regular files in scanned trees (FIFOs, devices, symlink loops) are
    skipped, counted in files_skipped, and never opened (A5b S-2);
  - exit 78 on bind conflict; binds 127.0.0.1 only — a wider bind fails loud;
  - home-path redaction on responses and on every path echoed back;
  - findings quote minimal spans; scanned contents are never echoed whole.

Deterministic responses: same corpus + same targets -> byte-identical scan
result (no timestamps, no counters in the payload).
"""

import json
import os
import socket
import sys

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("CONSTABLE_PORT", "4902"))  # dev override; manifest port 4902 is the contract
MAX_BODY = 64 * 1024
MAX_PATHS = 16
MAX_PATH_LEN = 1024

ADDON_ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(ADDON_ROOT, "corpus")

sys.path.insert(0, ADDON_ROOT)

import engine  # noqa: E402

BANNER = engine.RECEIPT_BANNER

# Identifier-ish strings (paths, ids) never carry control characters.
def _has_bad_control(text):
    for ch in text:
        o = ord(ch)
        if o == 0x7F or o < 0x20:
            return True
    return False


def _redact_text(text):
    home = os.path.expanduser("~")
    return text.replace(home, "~") if home and home != "~" else text


def _redact_obj(obj):
    if isinstance(obj, str):
        return _redact_text(obj)
    if isinstance(obj, list):
        return [_redact_obj(item) for item in obj]
    if isinstance(obj, dict):
        return {key: _redact_obj(value) for key, value in obj.items()}
    return obj


def _corpus_summary():
    index = engine.load_corpus(CORPUS_DIR)
    entries = index["entries"]
    return {
        "classes": len(index["classes"]),
        "entries": len(entries),
        "attacks": sum(1 for e in entries if e["label"] == "detect"),
        "typed_negatives": sum(1 for e in entries if e["label"] == "pass"),
        "defense_exemplars": sum(1 for e in entries if e["label"] == "reject"),
        "corpus_hash": engine.corpus_hash(CORPUS_DIR),
        "class_ids": sorted(c["id"] for c in index["classes"]),
    }


def _status_body():
    return {
        "ok": True,
        "addon": "addon.constable",
        "tool": "constable.status",
        "engine_version": engine.ENGINE_VERSION,
        "banner": BANNER,
        "rules": [r["id"] for r in engine.RULES],
        "doctrine_patterns": sorted({r["doctrine_pattern"] for r in engine.RULES}),
        "mode": "detect-and-explain",
        "capabilities_requested": ["filesystem"],
        "network": "none — loopback bind only, never dials out",
        "honesty_note": (
            "Known-answer is a rehearsal against the pinned corpus, which was "
            "co-developed with this checker; it proves the labels execute, "
            "not efficacy against the world."
        ),
    }


# ------------------------------------------------------------------ tools
def _t_status(params):
    return 200, _status_body()


def _t_scan(params):
    paths = params.get("paths")
    if not isinstance(paths, list) or not (1 <= len(paths) <= MAX_PATHS):
        return 400, {"error": f"paths must be an array of 1..{MAX_PATHS} strings"}
    resolved = []
    for item in paths:
        if not isinstance(item, str) or not (0 < len(item) <= MAX_PATH_LEN):
            return 400, {"error": "each path must be a string of 1..1024 characters"}
        if _has_bad_control(item):
            return 400, {"error": "path contains control characters"}
        if not os.path.isabs(item):
            return 400, {"error": "paths must be absolute (operator-scoped reads)"}
        if not os.path.exists(item):
            return 400, {"error": "path does not exist: " + _redact_text(item)}
        resolved.append(item)
    findings, files_scanned, files_skipped, findings_suppressed = engine.scan_paths(resolved)
    report = engine.build_report(resolved, findings, files_scanned, files_skipped,
                                 findings_suppressed)
    report["tool"] = "constable.scan"
    report["corpus_hash"] = engine.corpus_hash(CORPUS_DIR)
    return 200, report


def _t_corpus(params):
    summary = _corpus_summary()
    summary["tool"] = "constable.corpus"
    summary["banner"] = BANNER
    summary["index"] = [
        {
            "fixture_id": e["fixture_id"],
            "class": e["class"],
            "label": e["label"],
            "caught_by": e.get("caught_by"),
            "typed_negative_for": e.get("typed_negative_for"),
            "defense_of": e.get("defense_of"),
        }
        for e in engine.load_corpus(CORPUS_DIR)["entries"]
    ]
    return 200, summary


def _t_known_answer(params):
    receipt = engine.known_answer(CORPUS_DIR)
    receipt["tool"] = "constable.known_answer"
    return 200, receipt


_METHODS = {
    "constable.status": _t_status,
    "constable.scan": _t_scan,
    "constable.corpus": _t_corpus,
    "constable.known_answer": _t_known_answer,
}

_METHOD_PARAMS = {
    "constable.status": set(),
    "constable.scan": {"paths"},
    "constable.corpus": set(),
    "constable.known_answer": set(),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30  # a lying Content-Length must not pin a thread forever

    def _reply(self, code, payload, close=False):
        if close:
            self.close_connection = True  # never leave undrained bodies on a keep-alive connection
        body = json.dumps(_redact_obj(payload)).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if close:
            self.send_header("Connection", "close")  # advertise what the socket is about to do
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True  # client vanished mid-reply; never traceback

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._reply(200, _status_body())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/":
            self._reply(404, {"error": "not found"}, close=True)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "bad content-length"}, close=True)
            return
        if length <= 0 or length > MAX_BODY:
            self._reply(413 if length > MAX_BODY else 400,
                        {"error": "body must be 1..65536 bytes"}, close=True)
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except (TimeoutError, socket.timeout, OSError):
            self._reply(408, {"error": "request body incomplete (timeout)"}, close=True)
            return
        except (ValueError, UnicodeDecodeError, RecursionError):
            # RecursionError: some builds' json.loads recurse on deeply nested
            # bodies — same clean 400 either way (A5b S4 portability note)
            self._reply(400, {"error": "body must be valid JSON"}, close=True)
            return
        if not isinstance(req, dict):
            self._reply(400, {"error": "body must be a JSON object"}, close=True)
            return
        method = req.get("method")
        params = req.get("params", {})
        for key in req:
            if key not in ("method", "params"):
                self._reply(400, {"error": f"unknown field: {key}"}, close=True)
                return
        if not isinstance(method, str):
            self._reply(400, {"error": "method must be a string"}, close=True)
            return
        handler = _METHODS.get(method)
        if handler is None:
            self._reply(400, {"error": f"unknown tool: {method}"})
            return
        if not isinstance(params, dict):
            self._reply(400, {"error": "params must be an object"})
            return
        for key in params:
            if key not in _METHOD_PARAMS[method]:
                self._reply(400, {"error": f"unknown field: {key}"})
                return
        code, payload = handler(params)
        self._reply(code, payload)

    def log_message(self, fmt, *args):  # keep service logs quiet and content-free
        sys.stderr.write("constable-service: " + (fmt % args) + "\n")


def main():
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        sys.stderr.write(f"constable-service: cannot bind 127.0.0.1:{PORT} ({exc}); manifest entrypoint expects this port\n")
        return 78
    sys.stderr.write(f"constable-service: listening on http://127.0.0.1:{PORT}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

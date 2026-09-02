"""addon.constable service tests — the sibling local-service standard.

Covers: status honesty pins, the four tools, strict per-method param
allowlists, adversarial HTTP (413+close, 408+close, chunked 400,
control-chars 400, 20-req flood), home-path redaction, manifest parity
including port uniqueness against all sibling add-ons, and a whole-tree
privacy scan. The service runs in-process on an EPHEMERAL port here; the
live matrix on the manifest port 4902 is run separately (run-matrix.sh).

Run:  python3 -m unittest discover -s tests -v   (from the add-on root)
"""
import json
import os
import re
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
sys.path.insert(0, ADDON_ROOT)

import server  # noqa: E402
import engine  # noqa: E402

MANIFEST_PORT = 4902


def post(payload, raw=None, base=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request((base or BASE) + "/", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())


def post_err(payload, raw=None, base=None):
    try:
        return post(payload, raw, base)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read().decode())


def raw_request(payload_bytes, port, timeout=10):
    """One raw socket request; returns (status_line, response_bytes|None)."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(payload_bytes)
        try:
            data = sock.recv(65536)
            return data.split(b"\r\n", 1)[0].decode(), data
        except (ConnectionResetError, BrokenPipeError):
            return "connection-closed", None
    finally:
        sock.close()


class Service:
    """In-process service on an EPHEMERAL port (never the manifest port,
    which belongs to the deployed service contract and the live matrix)."""

    def __enter__(self):
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def url(self):
        return f"http://127.0.0.1:{self.port}"


BASE = ""


class TestServiceSurface(unittest.TestCase):
    def setUp(self):
        self.svc = Service()
        self.svc.__enter__()
        self.base = self.svc.url()
        self.addCleanup(self.svc.__exit__, None, None, None)

    def test_status_roundtrip_and_honesty_pins(self):
        code, body = post({"method": "constable.status"}, base=self.base)
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["addon"], "addon.constable")
        self.assertEqual(body["engine_version"], engine.ENGINE_VERSION)
        self.assertEqual(" ".join(body["banner"].split()),
                         " ".join(engine.RECEIPT_BANNER.split()))
        self.assertEqual(len(body["rules"]), 6)
        self.assertEqual(body["mode"], "detect-and-explain")
        self.assertIn("not efficacy", body["honesty_note"])

    def test_health_get(self):
        with urllib.request.urlopen(self.base + "/health", timeout=10) as resp:
            body = json.loads(resp.read().decode())
        self.assertTrue(body["ok"])

    def test_scan_over_the_pinned_attacks(self):
        attacks = os.path.join(ADDON_ROOT, "corpus", "fixtures", "attacks")
        code, body = post({"method": "constable.scan", "params": {"paths": [attacks]}},
                          base=self.base)
        self.assertEqual(code, 200)
        self.assertEqual(body["schema"], "constable-report/1")
        self.assertEqual(body["files_scanned"], 13)
        self.assertGreaterEqual(body["findings_count"], 13)
        self.assertEqual(body["mode"], "detect-and-explain")
        for finding in body["findings"]:
            self.assertIn("rule_id", finding)
            self.assertLessEqual(len(finding["excerpt"]), engine.MAX_EXCERPT + 6)

    def test_scan_is_operator_scoped(self):
        code, body = post_err({"method": "constable.scan",
                               "params": {"paths": ["/no/such/path/anywhere"]}},
                              base=self.base)
        self.assertEqual(code, 400)
        self.assertIn("does not exist", body["error"])
        code, body = post_err({"method": "constable.scan",
                               "params": {"paths": ["relative/path"]}},
                              base=self.base)
        self.assertEqual(code, 400)
        self.assertIn("absolute", body["error"])

    def test_corpus_tool_counts(self):
        code, body = post({"method": "constable.corpus"}, base=self.base)
        self.assertEqual(code, 200)
        self.assertEqual(body["classes"], 6)
        self.assertEqual(body["entries"], 27)
        self.assertEqual(body["attacks"], 13)
        self.assertEqual(body["typed_negatives"], 12)
        self.assertEqual(body["defense_exemplars"], 2)
        self.assertEqual(len(body["corpus_hash"]), 64)
        self.assertEqual(len(body["index"]), 27)

    def test_known_answer_tool_green(self):
        code, body = post({"method": "constable.known_answer"}, base=self.base)
        self.assertEqual(code, 200)
        self.assertTrue(body["all_pass"])
        self.assertEqual(body["attacks_detected"], 13)
        self.assertIn("not an efficacy claim", body["note"])


class TestStrictParams(unittest.TestCase):
    def setUp(self):
        self.svc = Service()
        self.svc.__enter__()
        self.base = self.svc.url()
        self.addCleanup(self.svc.__exit__, None, None, None)

    def test_unknown_tool_400(self):
        code, body = post_err({"method": "constable.execute"}, base=self.base)
        self.assertEqual(code, 400)
        self.assertIn("unknown tool", body["error"])

    def test_unknown_field_in_envelope_400(self):
        code, _ = post_err({"method": "constable.status", "extra": 1}, base=self.base)
        self.assertEqual(code, 400)

    def test_unknown_param_field_400(self):
        code, _ = post_err({"method": "constable.status", "params": {"evil": 1}},
                           base=self.base)
        self.assertEqual(code, 400)
        code, _ = post_err({"method": "constable.scan",
                            "params": {"paths": [], "evil": 1}}, base=self.base)
        self.assertEqual(code, 400)

    def test_control_chars_400(self):
        victim = os.path.join(ADDON_ROOT, "corpus", "fixtures", "attacks", "c1-shell-concat.py")
        code, body = post_err({"method": "constable.scan",
                               "params": {"paths": [victim.replace("c1", "c\x011")]}},
                              base=self.base)
        self.assertEqual(code, 400)
        self.assertIn("control characters", body["error"])  # the error names the mechanism

    def test_missing_required_param_400(self):
        code, _ = post_err({"method": "constable.scan", "params": {}}, base=self.base)
        self.assertEqual(code, 400)

    def test_non_object_body_400(self):
        code, _ = post_err(None, raw=b"[1,2,3]", base=self.base)
        self.assertEqual(code, 400)

    def test_invalid_json_400(self):
        code, _ = post_err(None, raw=b"{nope", base=self.base)
        self.assertEqual(code, 400)

    def test_bad_content_length_400(self):
        status, _ = raw_request(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: nope\r\n\r\n", self.svc.port)
        self.assertTrue(status.startswith("HTTP/1.1 400"), status)


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.svc = Service()
        self.svc.__enter__()
        self.base = self.svc.url()
        self.addCleanup(self.svc.__exit__, None, None, None)

    def test_scan_response_redacts_home_paths(self):
        home = os.path.expanduser("~")
        with tempfile.TemporaryDirectory() as tmp:
            victim = os.path.join(tmp, "note.py")
            with open(victim, "w", encoding="utf-8") as f:
                f.write("value = eval(payload)  # see " + home + "/secret-notes\n")
            code, body = post({"method": "constable.scan", "params": {"paths": [victim]}},
                              base=self.base)
            self.assertEqual(code, 200)
            wire = json.dumps(body)
            self.assertNotIn(home, wire, "home path leaked into the response")
            self.assertIn("~/secret-notes", wire)
            self.assertLess(max(len(f["excerpt"]) for f in body["findings"]),
                            engine.MAX_EXCERPT + 6)

    def test_no_home_paths_in_whole_tree(self):
        needle = (os.sep + "Users" + os.sep).encode()  # built at runtime so this file stays clean
        skip = {"__pycache__", ".git"}
        for root, dirs, files in os.walk(ADDON_ROOT):
            dirs[:] = [d for d in dirs if d not in skip]
            for name in files:
                if name.endswith(".pyc"):
                    continue
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    content = f.read()
                self.assertNotIn(needle, content, f"home path leaked in {path}")


class TestAdversarialHTTP(unittest.TestCase):
    def setUp(self):
        self.svc = Service()
        self.svc.__enter__()
        self.port = self.svc.port
        self.base = self.svc.url()
        self.addCleanup(self.svc.__exit__, None, None, None)

    def test_oversized_body_413_close_advertised(self):
        big = json.dumps({"method": "constable.status", "pad": "x" * 100000}).encode()
        self.assertGreater(len(big), server.MAX_BODY)
        status, data = raw_request(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(big)).encode()
            + b"\r\n\r\n" + big[:65536 + 1], self.port)
        self.assertTrue(status.startswith("HTTP/1.1 413"), status)
        self.assertIsNotNone(data)
        self.assertIn(b"Connection: close", data, "413 must advertise Connection: close")

    def test_lying_content_length_408_close(self):
        """Declaring more bytes than sent must not hang or misparse: 408 + close.
        Handler timeout is patched to 1s so the suite stays fast; production
        uses 30s (same code path)."""
        original_timeout = server.Handler.timeout
        server.Handler.timeout = 1
        try:
            status, data = raw_request(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n"
                b'{"method":"const', self.port)
            self.assertTrue(status.startswith("HTTP/1.1 408"), status)
            self.assertIsNotNone(data)
            self.assertIn(b"Connection: close", data)
        finally:
            server.Handler.timeout = original_timeout

    def test_chunked_encoding_400(self):
        status, _ = raw_request(
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"1a\r\n{\"method\":\"constable.status\"}\r\n0\r\n\r\n", self.port)
        self.assertTrue(status.startswith("HTTP/1.1 400"), status)

    def test_request_flood_20_concurrent(self):
        errors = []

        def hit(n):
            try:
                code, body = post({"method": "constable.status"}, base=self.base)
                if code != 200 or not body["ok"]:
                    errors.append((n, code))
            except Exception as exc:  # noqa: BLE001
                errors.append((n, repr(exc)))

        threads = [threading.Thread(target=hit, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(errors, [])


class TestManifestParity(unittest.TestCase):
    """The manifest must promise exactly what server.py serves."""

    ADDONS_DIR = os.path.dirname(ADDON_ROOT)

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ADDON_ROOT, "addon.json")) as f:
            cls.manifest = json.load(f)

    def test_manifest_id_and_entrypoint(self):
        self.assertEqual(self.manifest["id"], "addon.constable")
        self.assertEqual(self.manifest["service"]["entrypoint"],
                         f"http://127.0.0.1:{MANIFEST_PORT}")
        self.assertEqual(self.manifest["service"]["healthCommand"], "constable.status")
        self.assertEqual(self.manifest["service"]["protocol"], "http-json")

    def test_entrypoint_loopback_only(self):
        self.assertTrue(self.manifest["service"]["entrypoint"].startswith("http://127.0.0.1:"))

    def test_every_declared_tool_is_served(self):
        with open(os.path.join(ADDON_ROOT, "server.py")) as f:
            src = f.read()
        methods = []
        for tool in self.manifest["tools"]:
            self.assertIn(f'"{tool["name"]}"', src,
                          f"manifest tool not routed in server: {tool['name']}")
            self.assertIsInstance(tool["inputSchema"], dict)
            self.assertIsInstance(tool["outputSchema"], dict)
            self.assertEqual(tool["requiredCapabilities"], ["filesystem"])
            methods.append(tool["name"])
        self.assertEqual(len(methods), len(set(methods)))

    def test_no_undeclared_constable_methods_served(self):
        with open(os.path.join(ADDON_ROOT, "server.py")) as f:
            src = f.read()
        served = set(re.findall(r'"(constable\.[a-z_]+)"', src))
        declared = {t["name"] for t in self.manifest["tools"]}
        self.assertEqual(served, declared, "server surface and manifest tools diverged")

    def test_capability_posture(self):
        requested = self.manifest["requestedCapabilities"]
        self.assertEqual(len(requested), 1)
        self.assertEqual(requested[0]["capability"], "filesystem")
        self.assertFalse(requested[0]["granted"], "filesystem must ship ungranted (operator presets grant it)")
        self.assertEqual(requested[0]["revocationBehavior"], "hard-stop")
        self.assertEqual(len(self.manifest["grantPresets"]), 1)
        for tool in self.manifest["tools"]:
            self.assertFalse(tool["requiresHumanApproval"])
            self.assertTrue(tool["audit"]["logRequest"])

    def test_port_unique_across_all_siblings(self):
        """The manifest port must be UNUSED by every sibling add-on manifest."""
        collisions = []
        for name in sorted(os.listdir(self.ADDONS_DIR)):
            sibling = os.path.join(self.ADDONS_DIR, name)
            if name == os.path.basename(ADDON_ROOT) or not os.path.isdir(sibling):
                continue
            manifest_path = os.path.join(sibling, "addon.json")
            if not os.path.isfile(manifest_path):
                continue
            with open(manifest_path) as f:
                sibling_manifest = f.read()
            if f":{MANIFEST_PORT}" in sibling_manifest:
                collisions.append(name)
        self.assertEqual(collisions, [], f"port {MANIFEST_PORT} collides with: {collisions}")


if __name__ == "__main__":
    unittest.main()

"""A2 gate: corpus integrity — build-failing test.

Every corpus entry must carry: a class id known to the index, a public-class
citation on its class, a synthetic fixture file that exists, an expected-
outcome label from the pinned vocabulary, and the rule binding its label
requires. Typed-negative applicability is deterministic (corpus/README.md):
label pass implies typed_negative_for; every rule has >=1 negative; every
class has >=1 negative.

A5b fix-round gates in this file:
  - fixture CONTAINMENT (S-3): entry["fixture"] must be a clean RELATIVE
    path that resolves INSIDE corpus/fixtures — '..' traversal, absolute
    paths, and symlinks escaping the fixtures root are named integrity
    errors that fail the build (engine.resolve_fixture enforces the same
    rule inside engine.known_answer);
  - corpus-tree HYGIENE (S-2/C4): every file under corpus/ must be a
    REGULAR file and every symlink must resolve back inside corpus/ — a
    planted FIFO can no longer hang corpus_hash/known_answer and cannot
    pass this gate;
  - benign-fixture CONTENT (S-4): pass/reject fixtures are mechanically
    scanned (exact, whitespace-joined, and unicode-unescaped forms) for
    runnable-execution construction (getattr/eval/exec/compile/__import__,
    os.system/popen tokens in call or alias shape, the os posix_spawn/
    exec/spawn family, bare Function, the child_process shell-string
    family, dynamic-index execution over the global object, string-literal
    + string-literal assembly of execution names) — a hit fails the build.
    This gate is a HEURISTIC layer; the README's mandatory human review of
    every typed negative is the load-bearing certification (round-2 F-7).

Run:  python3 -m unittest discover -s tests -v   (from the add-on root)
"""
import json
import os
import re
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
sys.path.insert(0, ADDON_ROOT)

import engine  # noqa: E402

CORPUS_DIR = os.path.join(ADDON_ROOT, "corpus")
FIXTURES_DIR = os.path.join(CORPUS_DIR, "fixtures")
RULE_IDS = {r["id"] for r in engine.RULES}
LABELS = {"detect", "pass", "reject"}


# --------------------------------------------------------- A5b S-4 gate ---
# Mechanical runnable-execution construction heuristics over BENIGN fixture
# content (labels pass and reject). Patterns run against normalized forms of
# the fixture text: the exact bytes leniently decoded with NULs dropped, the
# whitespace-JOINED form that defeats cross-line splits (the E8d evasion:
# getattr(os, "sys"+"tem") split over two lines sails past every line-based
# rule), and unicode-UNESCAPED variants of both (round-2 F-7: JS "\\uXXXX"
# escapes and String.fromCharCode(...) assemble evaluator names —
# globalThis["\\u0065val"] — that a raw-text scan cannot see). A hit on a
# benign fixture fails the build.
#
# CLAIM, stated at its real strength (round-2 finding: the original gate
# docstring overclaimed): this gate is a HEURISTIC layer, not a decision
# procedure. It mechanically refuses the named construction families below;
# payloads can exist that resist every pattern here (general evasion is
# undecidable), so the README's rules of engagement pair this gate with
# mandatory HUMAN REVIEW of every typed negative, and that human layer —
# not this gate — is what finally certifies a negative benign. What this
# gate pins is: the corpus's benign fixtures must not contain the
# constructions the mechanical layer CAN name.
S4_CHECKS = (
    # dynamic evaluators and dynamic attribute construction (the C2 smuggle
    # shape: getattr(os, "sys" + "tem") followed by a call)
    (re.compile(r"(?<![\w.])(?:eval|exec|compile|__import__|getattr|import_module)\s*\("),
     "dynamic evaluator / getattr / import call"),
    # dynamic module import: import("child_process") / __import__("os")
    (re.compile(r"(?<![\w.])import\s*\(\s*['\"`]"),
     "dynamic module import call"),
    # os execution surface — TOKEN shape, paren NOT required: the round-2
    # F-7 P1 alias-then-call payload (`run = os.system` then `run(cmd)`)
    (re.compile(r"(?<![\w.])os\s*\.\s*(?:system|popen)\b"),
     "os system/popen token (call or alias shape)"),
    # os spawn/exec family in any whitespace shape — extended round-2 F-7 P2
    # to cover posix_spawn / posix_spawnp
    (re.compile(r"(?<![\w.])os\s*\.\s*(?:posix_spawn\w*|execv\w*|spawn\w*)\s*\("),
     "os posix_spawn/exec/spawn call"),
    # a bare system() call is not benign in any of the corpus's languages —
    # and neither is <anything>.system( (an aliased os module: the dot is not
    # allowed to hide the call, the round-2 R-e probe shape)
    (re.compile(r"(?<![\w])system\s*\("),
     "bare or aliased system() call"),
    # alias-then-call: any assignment whose RHS is a bare execution-function
    # name (round-2 F-7 P1 generalization; catches `x = eval; x(cmd)`)
    (re.compile(r"=\s*(?:execSync|eval|exec|system|popen|getattr)\b"),
     "assignment of a bare execution function (alias-then-call shape)"),
    # JS dynamic construction: bare Function( covers `new Function(...)` AND
    # the round-2 F-7 P3 indirect form `Function("return 40 + 2")()`
    (re.compile(r"(?<![\w.])Function\s*\("),
     "Function(...) dynamic construction (new or bare)"),
    # node child_process shell-string runners — the round-2 F-7 P4 payload;
    # argv-form execFileSync stays out of scope on purpose (it is the
    # corpus's own benign shell-less shape)
    (re.compile(r"(?<![\w.])child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync|fork)\s*\("),
     "child_process exec/spawn family call"),
    # execSync( is a shell-string runner in every shape it appears — dotted
    # alias included (`cp.execSync(` where cp aliases child_process)
    (re.compile(r"(?<![\w])execSync\s*\("),
     "bare or aliased execSync() shell-string runner"),
    # reflection over the execution modules
    (re.compile(r"(?<![\w.])(?:vars|globals)\s*\(\s*(?:os|subprocess|importlib|builtins)\b"),
     "vars()/globals() over an execution module"),
    # dynamic-index execution over the global object (round-2 F-7 P5 shape:
    # globalThis["\\u0065val"](...) — this pattern catches the bracketed
    # global-object access itself, whatever the (un)escaped member name)
    (re.compile(r"(?<![\w.])(?:globalThis|global|window|self)\s*\["),
     "dynamic-index execution over the global object"),
    # dynamic member call by string literal name: obj["eval"](...)
    (re.compile(r"\[\s*['\"][A-Za-z_$][A-Za-z0-9_$]*['\"]\s*\]\s*\("),
     "bracketed string-name call (dynamic dispatch by literal name)"),
    # assembly of names from string-literal pieces ("sys" + "tem"), however
    # used — backtick template literals included (the round-2 R-d probe:
    # `ev` + `al`)
    (re.compile(r"[`'\"][A-Za-z_$][A-Za-z0-9_$]{0,63}[`'\"]\s*\+\s*[`'\"][A-Za-z_$][A-Za-z0-9_$]{0,63}[`'\"]"),
     "string-literal + string-literal concatenation (execution-name assembly shape)"),
)

_JS_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_FROM_CHAR_CODE_RE = re.compile(
    r"String\s*\.\s*fromCharCode\s*\(\s*(?:0[xX][0-9a-fA-F]+|[0-9]+)"
    r"(?:\s*,\s*(?:0[xX][0-9a-fA-F]+|[0-9]+))*\s*\)")


def _s4_unescape(text):
    """Round-2 F-7 P5 normalization: decode JS \\uXXXX escapes and
    String.fromCharCode(...) sequences so evaluator names assembled that way
    present their runtime shape to the pattern scan. Applied as a bounded
    fixpoint loop (an escape can decode INTO another encoding trick)."""
    def decode_from_char_code(match):
        codes = re.findall(r"0[xX][0-9a-fA-F]+|[0-9]+", match.group(0))
        return "".join(
            chr(int(code, 16 if code.lower().startswith("0x") else 10) % 0x110000)
            for code in codes)
    for _ in range(5):
        unescaped = _JS_UNICODE_ESCAPE_RE.sub(
            lambda m: chr(int(m.group(1), 16)), text)
        unescaped = _FROM_CHAR_CODE_RE.sub(decode_from_char_code, unescaped)
        if unescaped == text:
            break
        text = unescaped
    return text


def s4_normalized_forms(raw):
    """The normalized scan forms for a fixture's raw bytes as (text, name)
    pairs: lenient decode with NULs dropped, then the exact form and the
    whitespace-joined form, each in raw and unicode-unescaped variants
    (round-2 F-7 P5)."""
    text = raw.decode("utf-8", errors="replace").replace("\x00", "")
    joined = " ".join(text.split())
    return (
        (text, "exact"),
        (_s4_unescape(text), "exact-unescaped"),
        (joined, "whitespace-joined"),
        (_s4_unescape(joined), "whitespace-joined-unescaped"),
    )


def s4_scan_benign_fixture(raw):
    """Returns a list of (reason, form) hits; empty means the fixture is
    mechanically clean of runnable-execution construction UNDER THE NAMED
    PATTERNS — not proof of benignity (the human-review layer is
    load-bearing; see the gate comment above)."""
    hits = []
    for form, form_name in s4_normalized_forms(raw):
        for pattern, reason in S4_CHECKS:
            if pattern.search(form):
                hits.append((reason, form_name))
    return hits


def load_index():
    with open(os.path.join(CORPUS_DIR, "corpus.json"), "rb") as f:
        return json.loads(f.read().decode("utf-8"))


class TestCorpusIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = load_index()

    def test_index_schema_and_banner(self):
        self.assertEqual(self.index["schema"], engine.CORPUS_SCHEMA)
        self.assertEqual(" ".join(self.index["banner"].split()),
                         " ".join(engine.RECEIPT_BANNER.split()))
        self.assertIn("typed_negative_applicability", self.index)

    def test_classes_have_public_citations(self):
        classes = {c["id"]: c for c in self.index["classes"]}
        self.assertEqual(len(classes), len(self.index["classes"]), "duplicate class id")
        for cid, c in classes.items():
            self.assertIn("name", c, cid)
            citation = c.get("citation", "")
            self.assertTrue(
                ("cwe.mitre.org" in citation) or ("owasp.org" in citation),
                f"{cid}: class citation must be a public reference (CWE or OWASP): {citation!r}",
            )
            self.assertIn(c.get("rule_id"), RULE_IDS, f"{cid}: unknown rule binding")
            self.assertTrue(
                re.match(r"^P[1-4]-[a-z-]+$", c.get("doctrine_pattern", "")),
                f"{cid}: doctrine pattern not in the P1-P4 vocabulary",
            )

    def test_every_entry_has_every_required_field(self):
        entries = self.index["entries"]
        self.assertGreaterEqual(len(entries), 20)
        seen = set()
        for e in entries:
            fid = e.get("fixture_id")
            self.assertTrue(fid, f"entry missing fixture_id: {e!r}")
            self.assertNotIn(fid, seen, f"duplicate fixture_id: {fid}")
            seen.add(fid)
            self.assertIn(e.get("class"), {c["id"] for c in self.index["classes"]},
                          f"{fid}: unknown class id")
            self.assertIn(e.get("label"), LABELS, f"{fid}: label outside vocabulary")
            # A5b S-3 gate: fixture paths are strictly contained. Traversal,
            # absolute paths, and symlink escapes each fail with a named reason.
            resolved, reason = engine.resolve_fixture(FIXTURES_DIR, e.get("fixture"))
            self.assertIsNone(
                reason,
                f"{fid}: fixture path rejected: {reason} ({e.get('fixture')!r})")
            self.assertTrue(os.path.isfile(resolved),
                            f"{fid}: fixture file missing: {e.get('fixture')}")
            size = os.path.getsize(resolved)
            self.assertGreater(size, 0, f"{fid}: empty fixture")
            self.assertLess(size, engine.MAX_FILE_BYTES, f"{fid}: fixture oversized")
            if e["label"] == "detect":
                self.assertIn(e.get("caught_by"), RULE_IDS,
                              f"{fid}: detect entry must name a known caught_by rule")
            elif e["label"] == "pass":
                self.assertIn(e.get("typed_negative_for"), RULE_IDS,
                              f"{fid}: pass entry must name its typed_negative_for rule")
            elif e["label"] == "reject":
                self.assertIn(e.get("defense_of"), RULE_IDS,
                              f"{fid}: reject entry must name its defense_of rule")

    def test_corpus_tree_is_regular_files_inside_the_root(self):
        """A5b S-2/C4 gate-side integrity: corpus_hash and known_answer must
        never be able to hang or read outside the corpus. Every file under
        corpus/ must be a REGULAR file; any symlink must resolve back INSIDE
        corpus/. A planted FIFO, device file, or escaping symlink is a named
        integrity error that fails the build."""
        root = os.path.realpath(CORPUS_DIR)
        offenders = []
        for dirpath, dirs, names in os.walk(root):
            for name in dirs:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    target = os.path.realpath(path)
                    if not target.startswith(root + os.sep):
                        offenders.append(path + ": symlinked directory escapes corpus/ -> " + target)
            for name in sorted(names):
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    target = os.path.realpath(path)
                    if not target.startswith(root + os.sep):
                        offenders.append(path + ": symlink escapes corpus/ -> " + target)
                    continue
                mode = os.lstat(path).st_mode
                if not stat.S_ISREG(mode):
                    offenders.append(
                        path + ": not a regular file (format " + oct(stat.S_IFMT(mode))
                        + ") — would hang or poison the corpus read set")
        self.assertEqual(offenders, [], "corpus tree hygiene failures")

    def test_corpus_hash_framing_resists_the_round2_splice(self):
        """Round-2 F-8 regression: the digest stream is LENGTH-FRAMED per
        record. Under the old `rel \\0 content \\0` framing, two corpora
        differing exactly by the splice below hashed IDENTICAL — corpus B's
        single fixture content carries NUL + a forged relpath + corpus A's
        second fixture, forging the next record without moving the hash.
        With length framing the forged record is unconstructable."""
        def build(root, spliced):
            os.makedirs(root)
            c1, c2 = b"content-one", b"content-two"
            with open(os.path.join(root, "corpus.json"), "wb") as f:
                f.write(b'{"schema": "constable-corpus/1"}')
            with open(os.path.join(root, "a.py"), "wb") as f:
                if spliced:
                    f.write(c1 + b"\x00" + b"b.py" + b"\x00" + c2)
                else:
                    f.write(c1)
            if not spliced:
                with open(os.path.join(root, "b.py"), "wb") as f:
                    f.write(c2)
            return engine.corpus_hash(root)

        with tempfile.TemporaryDirectory() as tmp:
            hash_a = build(os.path.join(tmp, "a"), spliced=False)
            hash_b = build(os.path.join(tmp, "b"), spliced=True)
        self.assertNotEqual(hash_a, hash_b,
                            "framing splice collided: two corpus shapes share one digest")
        # sanity: hashing is stable over the same bytes
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(build(os.path.join(tmp, "a"), spliced=False),
                             build(os.path.join(tmp, "a2"), spliced=False))

    def test_corpus_reads_are_size_bounded(self):
        """Round-2 F-4 regression: corpus_hash caps per-file reads at
        MAX_FILE_BYTES (a 3 GB junk file under corpus/ drove max RSS to
        3.24 GB in the round-2 battery), and load_corpus refuses a corpus.json
        over the size bound with a named error instead of parsing it."""
        with tempfile.TemporaryDirectory() as tmp:
            junk = os.path.join(tmp, "junk-sparse.bin")
            with open(junk, "wb") as f:
                f.seek(engine.MAX_FILE_BYTES + (1 << 20))
                f.write(b"\0")
            with open(os.path.join(tmp, "corpus.json"), "wb") as f:
                f.write(b'{"schema": "constable-corpus/1"}')
            digest = engine.corpus_hash(tmp)  # must complete, bounded
            self.assertEqual(len(digest), 64)
            # bounded PROOF: the hash equals the hash of the same tree with
            # the junk truncated to the cap — bytes beyond the cap are never
            # read
            with open(junk, "r+b") as f:
                f.truncate(engine.MAX_FILE_BYTES)
            self.assertEqual(engine.corpus_hash(tmp), digest)

    def test_benign_fixtures_contain_no_runnable_execution_construction(self):
        """A5b S-4 gate: pass/reject fixture CONTENT is mechanically scanned
        (exact, whitespace-joined, and unicode-unescaped normalized forms)
        for runnable-execution construction; a hit fails the build with a
        named reason. Claim at its real strength (round-2 F-7): this gate
        pins the constructions the mechanical layer CAN name — it does not
        certify benignity. General evasion is undecidable, so the README's
        mandatory HUMAN REVIEW of every typed negative is the load-bearing
        certification layer."""
        checked = 0
        for e in self.index["entries"]:
            if e["label"] not in ("pass", "reject"):
                continue
            resolved, reason = engine.resolve_fixture(FIXTURES_DIR, e.get("fixture"))
            if reason is not None:
                continue  # reported with a named reason by the containment gate
            with open(resolved, "rb") as f:
                raw = f.read()
            hits = s4_scan_benign_fixture(raw)
            self.assertEqual(
                hits, [],
                f"{e['fixture_id']}: runnable-execution construction in a benign "
                f"fixture ({e['fixture']}): " + "; ".join(f"{r} [{form}]" for r, form in hits))
            checked += 1
        self.assertGreaterEqual(checked, 14, "gate scanned too few benign fixtures to count")

    def test_s4_gate_fires_on_the_getattr_concat_smuggle(self):
        """The C2/E8d smuggle shape must be mechanically rejected wherever it
        hides — exact form and split across lines."""
        smuggle = b'fn = getattr(os, "sys" + "tem")\nfn("ls")\n'
        self.assertTrue(s4_scan_benign_fixture(smuggle), "gate missed the exact-form smuggle")
        split = b'fn = getattr(os,\n  "sys" + "tem")\nfn("ls")\n'
        self.assertTrue(s4_scan_benign_fixture(split), "gate missed the cross-line-split smuggle")
        eval_concat = b'result = eval("sys" + "tem")\n'
        self.assertTrue(s4_scan_benign_fixture(eval_concat), "gate missed eval-of-concat")
        exec_concat = b'exec("im" + "port os")\n'
        self.assertTrue(s4_scan_benign_fixture(exec_concat), "gate missed exec-of-concat")
        spaced = b'os . system (cmd)\n'
        self.assertTrue(s4_scan_benign_fixture(spaced), "gate missed the whitespace-tolerant os.system form")

    def test_s4_gate_fires_on_every_round2_f7_payload(self):
        """Round-2 F-7 regression: all five payloads that mechanically
        bypassed the original gate must now be caught in at least one
        normalized form. These are TEST payloads — the corpus itself stays
        27 entries (the A4 known-answer counts are unchanged by design)."""
        payloads = (
            (b'import os\nrun = os.system\nrun(user_cmd)\n',
             "P1 alias-then-call (run = os.system)"),
            (b'import os\nos.posix_spawn("/bin/sh", ["/bin/sh", "-c", user_cmd], os.environ)\n',
             "P2 os.posix_spawn"),
            (b'const f = Function("return 40 + 2"); console.log(f());\n',
             "P3 bare Function(...)()"),
            (b'const cp = require("child_process");\ncp.execSync(userCmd);\n'
             b'child_process.execSync(userCmd);\n',
             "P4 child_process.execSync"),
            (b'globalThis["\\u0065val"]("40 + 2");\n',
             "P5 unicode-escaped dynamic-index eval"),
            (b'globalThis[String.fromCharCode(101, 118, 97, 108)]("40 + 2");\n',
             "P5b String.fromCharCode dynamic-index eval"),
            (b'const evil = eval;\nevil(user_cmd);\n',
             "P1b bare-evaluator alias (x = eval)"),
        )
        for payload, name in payloads:
            hits = s4_scan_benign_fixture(payload)
            self.assertTrue(hits, f"S-4 gate MISSED the round-2 payload: {name}")

    def test_s4_unescape_normalizer_decodes_hidden_names(self):
        """The unicode-escape normalization must expose the runtime shape:
        after unescaping, the evaluator name is literally present in the
        unescaped form."""
        forms = {name: text for text, name in
                 s4_normalized_forms(b'globalThis["\\u0065val"]("x");')}
        self.assertIn("eval", forms["exact-unescaped"])
        self.assertNotIn("eval", forms["exact"])  # the raw form really hid it

    def test_typed_negative_applicability_rule(self):
        """The deterministic rule from corpus/README.md."""
        entries = self.index["entries"]
        by_rule_negatives = {}
        by_class_negatives = {}
        for e in entries:
            if e["label"] == "pass":
                by_rule_negatives.setdefault(e["typed_negative_for"], []).append(e)
                by_class_negatives.setdefault(e["class"], []).append(e)
        for rule_id in RULE_IDS:
            self.assertIn(rule_id, by_rule_negatives,
                          f"defense pattern {rule_id} has no typed negative")
        class_ids = {c["id"] for c in self.index["classes"]}
        for cid in class_ids:
            self.assertIn(cid, by_class_negatives,
                          f"class {cid} has no typed negative (no benign lookalike recorded)")

    def test_every_rule_and_class_referenced_by_attacks(self):
        attacks_by_rule = {}
        for e in self.index["entries"]:
            if e["label"] == "detect":
                attacks_by_rule.setdefault(e["caught_by"], []).append(e["fixture_id"])
        for rule_id in RULE_IDS:
            self.assertIn(rule_id, attacks_by_rule,
                          f"rule {rule_id} has no attack fixture; the corpus must exercise every defense")
        self.assertGreaterEqual(len(attacks_by_rule), 6, "at least 6 attack classes required")

    def test_matrix_rows_match_entries(self):
        with open(os.path.join(CORPUS_DIR, "MATRIX.md"), encoding="utf-8") as f:
            matrix = f.read()
        for e in self.index["entries"]:
            self.assertIn(e["fixture_id"], matrix,
                          f"{e['fixture_id']} missing from corpus/MATRIX.md")

    def test_corpus_readme_states_applicability_rule(self):
        with open(os.path.join(CORPUS_DIR, "README.md"), encoding="utf-8") as f:
            body = f.read()
        self.assertIn("Every **defense pattern**", body)
        self.assertIn("carries at least one typed", body)
        self.assertIn("every class carries at least one typed negative", body)


if __name__ == "__main__":
    unittest.main()

"""A8 gate: claims + redaction.

- The receipt banner is present in README.md VERBATIM and pinned here; the
  same test pins the A4 non-efficacy sentence (critic note: same docs test
  as the banner); the engine and service carry the identical banner
  constant.
- Log redaction: scanned content never appears whole in any output; the
  engine's stdout log lines carry no scanned content; findings quote
  minimal spans (bounded excerpt); home paths are redacted to "~" on disk
  and in every output.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
sys.path.insert(0, ADDON_ROOT)

import engine  # noqa: E402

ENGINE = os.path.join(ADDON_ROOT, "engine.py")
BANNER = engine.RECEIPT_BANNER
A4_SENTENCE = (
    "Because corpus and checker are co-developed, the known-answer run proves the "
    "checker executes its own labels \u2014 it is NOT an efficacy claim against the "
    "world."
)


def normalized(text):
    return " ".join(text.split())


class TestDocsPins(unittest.TestCase):
    def test_receipt_banner_verbatim_in_readme(self):
        with open(os.path.join(ADDON_ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn(normalized(BANNER), normalized(readme),
                      "README must carry the receipt banner verbatim (whitespace-insensitive)")

    def test_a4_non_efficacy_sentence_pinned_in_readme(self):
        with open(os.path.join(ADDON_ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn(normalized(A4_SENTENCE), normalized(readme))

    def test_banner_constant_identical_across_engine_server_and_corpus_index(self):
        import server
        with open(os.path.join(ADDON_ROOT, "corpus", "corpus.json"), encoding="utf-8") as f:
            index = json.load(f)
        self.assertEqual(normalized(index["banner"]), normalized(BANNER))
        self.assertEqual(normalized(server.BANNER), normalized(BANNER))
        with open(ENGINE, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("This kit teaches a defense discipline and ships a reference checker.",
                      src, "engine.py must carry the banner as literal constants")

    def test_doctrine_carries_the_banner_and_claims_clause(self):
        with open(os.path.join(ADDON_ROOT, "docs", "DOCTRINE.md"), encoding="utf-8") as f:
            doctrine = f.read()
        self.assertIn(normalized(BANNER), normalized(doctrine))


class TestRedaction(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, ENGINE, *args],
                              capture_output=True, cwd=ADDON_ROOT)

    def test_home_path_redacted_and_content_never_echoed_whole(self):
        home = os.path.expanduser("~")
        fd, victim = tempfile.mkstemp(dir=home, prefix="constable-redaction-probe-", suffix=".py")
        os.close(fd)
        try:
            # one huge single line so a whole-content echo would be unmissable
            with open(victim, "w", encoding="utf-8") as f:
                f.write("note = os.system('cat ' + path)  # " + home + "/private/notes "
                        + "z" * 4000 + "\n")
            done = self._run(victim, "--text")
            self.assertEqual(done.returncode, 0)
            out = done.stdout.decode()
            self.assertNotIn(home, out, "home path leaked into the report")
            self.assertIn("~/private/notes", out)
            # minimal-span law: no output line may carry the whole 4KB line
            longest = max(len(line) for line in out.splitlines())
            self.assertLess(longest, 400, "output echoed a whole scanned line")
            # JSON report path echoes are redacted too
            done = self._run(victim)
            report = json.loads(done.stdout.decode())
            self.assertEqual(report["findings_count"], 1)
            self.assertNotIn(home, done.stdout.decode())
            self.assertTrue(report["findings"][0]["path"].startswith("~"),
                            "path under home must be reported as ~/")
            self.assertTrue(report["targets"][0].startswith("~"))
        finally:
            os.remove(victim)

    def test_stdout_log_lines_are_content_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim = os.path.join(tmp, "x.py")
            marker = "VERYSECRETMARKER"
            with open(victim, "w", encoding="utf-8") as f:
                f.write("value = eval(payload)  # " + marker + "\n")
            done = self._run(victim, "--out", os.path.join(tmp, "out.json"))
            self.assertEqual(done.returncode, 0)
            self.assertNotIn(marker, done.stdout.decode(),
                             "stdout log line carried scanned content")
            # the report FILE may quote the minimal span, never the whole file
            with open(os.path.join(tmp, "out.json"), encoding="utf-8") as f:
                report = json.load(f)
            excerpt = report["findings"][0]["excerpt"]
            self.assertIn(marker, excerpt)  # the span itself is the finding evidence
            self.assertLess(len(excerpt), 200)

    def test_excerpt_hard_cap(self):
        long_line = "os.system('echo hi')  # " + "q" * 5000
        with tempfile.TemporaryDirectory() as tmp:
            victim = os.path.join(tmp, "long.py")
            with open(victim, "w", encoding="utf-8") as f:
                f.write(long_line + "\n")
            findings = engine.scan_file(victim)
            self.assertEqual(len(findings), 1)
            self.assertLessEqual(len(findings[0]["excerpt"]), engine.MAX_EXCERPT + 6)

    def test_text_report_escapes_c1_and_unicode_line_forgeries(self):
        """A5b round-2 F-1/F-1b: C1 controls (0x7F-0x9F), the Unicode
        line/paragraph separators, the RTL override, and the zero-width
        space must never reach --text output raw — byte-level assertion, so
        the escape holds on C1-honoring terminals too, not only the
        target platform. Covers BOTH smuggle carriers: the filename and
        the file-content excerpt."""
        with tempfile.TemporaryDirectory() as tmp:
            hostile_name = "c1-\u009b31m\u0085\u2028\u2029\u202e\u200b.py"
            victim = os.path.join(tmp, hostile_name)
            with open(victim, "w", encoding="utf-8") as f:
                # U+202E/U+200B ride INSIDE the matched line; U+2028/U+2029
                # are splitlines() boundaries (round-1 F-1d), so they end the
                # excerpt — everything after them is a separate pseudo-line
                f.write("value = eval(payload)  # ok\u009b8;1m\u202efake\u200bdir\u2028forged\u2029tail\n")
            done = self._run(victim, "--text")
            self.assertEqual(done.returncode, 0)
            raw_out = done.stdout
            # byte-level: no raw C1 / separator / override / zero-width /
            # ESC byte anywhere in the text report
            for raw_bytes, label in (
                    (b"\xc2\x9b", "U+009B CSI"), (b"\xc2\x85", "U+0085 NEL"),
                    (b"\xe2\x80\xa8", "U+2028 LS"), (b"\xe2\x80\xa9", "U+2029 PS"),
                    (b"\xe2\x80\xae", "U+202E RLO"), (b"\xe2\x80\x8b", "U+200B ZWSP"),
                    (b"\x1b", "ESC")):
                self.assertNotIn(raw_bytes, raw_out,
                                 label + " reached the text report raw")
            # the escaped spellings are what a human reader sees instead
            for escaped in (b"\\u009b", b"\\u0085", b"\\u2028", b"\\u2029",
                            b"\\u202e", b"\\u200b"):
                self.assertIn(escaped, raw_out,
                              escaped.decode() + " missing from the escaped report")
            # report-line forgery stays dead: exactly one real matched:/fix: pair
            out_lines = raw_out.decode("utf-8").splitlines()
            self.assertEqual(
                out_lines.count("  matched: value = eval(payload)  # "
                                "ok\\u009b8;1m\\u202efake\\u200bdir"), 1)
            self.assertEqual(out_lines.count("  fix: Never evaluate stored content: "
                                             "dispatch through a fixed table of functions, "
                                             "or parse the value with a fixed grammar and "
                                             "compare against known constants."), 1)

    def test_c1_only_filename_is_escaped_in_text_mode(self):
        """F-1: a C1-only hostile filename (no C0 chars — the original S-1
        class was already covered) is also escaped."""
        with tempfile.TemporaryDirectory() as tmp:
            victim = os.path.join(tmp, "\u009b31m-fake.py")
            with open(victim, "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            done = self._run(victim, "--text")
            self.assertEqual(done.returncode, 0)
            self.assertNotIn(b"\xc2\x9b", done.stdout)
            self.assertIn(b"\\u009b31m-fake.py", done.stdout)


if __name__ == "__main__":
    unittest.main()

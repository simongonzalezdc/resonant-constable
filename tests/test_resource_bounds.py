"""A5b round-2 F-4/F-5 gate: resource bounds — build-failing tests.

The round-2 adversary battery demonstrated two amplification channels:

  - F-4: an unindexed multi-GB file under corpus/ was slurped WHOLE by
    corpus_hash (max RSS 3.24 GB from one sparse file) — closed in the
    engine by capping every corpus read at MAX_FILE_BYTES (the corpus-hash
    half of that gate is regression-pinned in test_corpus_integrity.py;
    the load_corpus refusal is pinned here);
  - F-5: one 8 MB-capped file of tiny matching lines produced 254,200
    finding dicts (649 MB RSS, 159 MB JSON report) — closed by the
    per-file cap (MAX_FINDINGS_PER_FILE) and the per-report cap
    (MAX_FINDINGS), with honest findings_truncated/findings_suppressed
    fields and a loud text-mode banner.

Run:  python3 -m unittest discover -s tests -v   (from the add-on root)
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
sys.path.insert(0, ADDON_ROOT)

import engine  # noqa: E402

ENGINE = os.path.join(ADDON_ROOT, "engine.py")
MATCHING_LINE = "value = os.system('x')\n"


class TestFindingsCaps(unittest.TestCase):
    def test_scan_paths_caps_findings_with_honest_suppression(self):
        """F-5: a tree of matching-line amplifiers degrades to a bounded,
        honestly-labeled report: len(findings) <= MAX_FINDINGS, and the
        suppressed count names exactly what the caps dropped."""
        with tempfile.TemporaryDirectory() as tmp:
            # file 1 blows the PER-FILE cap (1200 matches, 500 kept, 700 suppressed)
            with open(os.path.join(tmp, "per-file.py"), "w", encoding="utf-8") as f:
                f.write(MATCHING_LINE * 1200)
            # files 2+3 blow the PER-REPORT cap (400 each: 900 -> 1000 kept,
            # 300 suppressed at report scope)
            for name in ("r2.py", "r3.py"):
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as f:
                    f.write(MATCHING_LINE * 400)
            findings, scanned, skipped, suppressed = engine.scan_paths([tmp])
            self.assertEqual(scanned, 3)
            self.assertEqual(skipped, 0)
            self.assertLessEqual(len(findings), engine.MAX_FINDINGS)
            self.assertEqual(len(findings), engine.MAX_FINDINGS,
                             "report cap should bind exactly for this tree")
            self.assertEqual(
                suppressed,
                (1200 - engine.MAX_FINDINGS_PER_FILE)   # per-file suppression
                + (800 - (engine.MAX_FINDINGS - engine.MAX_FINDINGS_PER_FILE)),
                "suppressed count must account for both caps exactly")

    def test_report_fields_name_the_truncation(self):
        findings, scanned, skipped, suppressed = engine.scan_paths(
            [os.path.dirname(os.path.abspath(__file__))])  # tests/ has no matches
        report = engine.build_report(["x"], findings, scanned, skipped, suppressed)
        # the fields are ALWAYS present (honesty by construction)...
        self.assertIn("findings_truncated", report)
        self.assertIn("findings_suppressed", report)
        self.assertFalse(report["findings_truncated"])
        self.assertEqual(report["findings_suppressed"], 0)

    def test_cli_text_banner_names_the_suppressed_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "amplifier.py"), "w", encoding="utf-8") as f:
                f.write(MATCHING_LINE * 1200)
            done = subprocess.run([sys.executable, ENGINE, tmp, "--text"],
                                  capture_output=True, cwd=ADDON_ROOT)
            self.assertEqual(done.returncode, 0, done.stderr.decode())
            out = done.stdout.decode()
            self.assertIn("findings capped at " + str(engine.MAX_FINDINGS), out)
            self.assertIn("700 further findings suppressed", out)
            # JSON mode carries the same truth
            done = subprocess.run([sys.executable, ENGINE, tmp],
                                  capture_output=True, cwd=ADDON_ROOT)
            report = json.loads(done.stdout.decode())
            self.assertTrue(report["findings_truncated"])
            self.assertEqual(report["findings_suppressed"], 700)
            self.assertLessEqual(report["findings_count"], engine.MAX_FINDINGS)


class TestCorpusIndexBound(unittest.TestCase):
    def test_load_corpus_refuses_an_oversized_index(self):
        """F-4 (index half): a corpus.json over MAX_INDEX_BYTES is refused
        with a named error — the parse is size-bounded like every other
        read, never an unbounded blob."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "corpus.json"), "wb") as f:
                f.write(b'{"schema": "constable-corpus/1", "pad": "')
                f.write(b"x" * (engine.MAX_INDEX_BYTES + 1))
                f.write(b'"}')
            with self.assertRaises(SystemExit) as ctx:
                engine.load_corpus(tmp)
            self.assertIn("refusing to parse", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

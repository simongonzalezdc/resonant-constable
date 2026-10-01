"""A4 gate: known-answer ground truth (the wind-tunnel standard).

On the pinned corpus, the checker must identify 100% of attack fixtures per
their labels (at least via the named caught_by rule) and 100% of benign
fixtures and defense exemplars must pass clean. SCOPE (architect note):
corpus and checker are co-developed, so this proves the checker executes
its own labels — it is NOT an efficacy claim against the world; README
says so in one pinned sentence.
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

CORPUS_DIR = os.path.join(ADDON_ROOT, "corpus")
ENGINE = os.path.join(ADDON_ROOT, "engine.py")


class TestKnownAnswer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = engine.known_answer(CORPUS_DIR)

    def test_known_answer_is_100_percent(self):
        self.assertTrue(self.receipt["all_pass"], "known answer below 100%")
        failures = [r for r in self.receipt["results"] if not r["pass"]]
        self.assertEqual(failures, [])

    def test_every_attack_fixture_caught_via_its_labelled_rule(self):
        for r in self.receipt["results"]:
            if r["label"] != "detect":
                continue
            fixture = os.path.join(CORPUS_DIR, "fixtures", r["file"])
            fired = {f["rule_id"] for f in engine.scan_file(fixture)}
            entry = next(e for e in json.load(open(os.path.join(CORPUS_DIR, "corpus.json")))["entries"]
                         if e["fixture"] == r["file"])
            self.assertIn(entry["caught_by"], fired,
                          f"{r['fixture_id']}: labelled rule {entry['caught_by']} did not fire")

    def test_negatives_and_defenses_stay_silent(self):
        for r in self.receipt["results"]:
            if r["label"] in ("pass", "reject"):
                self.assertEqual(r["detail"], "clean", r["fixture_id"])

    def test_counts_match_the_pinned_corpus(self):
        self.assertEqual(self.receipt["attacks_total"], 13)
        self.assertEqual(self.receipt["negatives_total"], 12)
        self.assertEqual(self.receipt["defenses_total"], 2)
        self.assertEqual(self.receipt["attacks_detected"], 13)
        self.assertEqual(self.receipt["negatives_clean"], 12)
        self.assertEqual(self.receipt["defenses_clean"], 2)

    def test_cli_known_answer_exit_zero_and_receipt_hash_present(self):
        done = subprocess.run([sys.executable, ENGINE, "--known-answer"],
                              capture_output=True, cwd=ADDON_ROOT)
        self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
        payload = json.loads(done.stdout.decode())
        self.assertTrue(payload["all_pass"])
        self.assertEqual(len(payload["corpus_hash"]), 64)
        self.assertIn("not an efficacy claim", payload["note"])

    def test_missing_fixture_is_a_named_failure_never_a_phantom_clean(self):
        """A5b round-2 F-6a defense in depth: a corpus entry whose fixture
        file is ABSENT (contained path, file not there) must FAIL the
        known answer with a named reason — the pre-fix engine reported a
        silent phantom 'clean' negative for it (the A2 gate catches this
        pre-merge; the engine now refuses too)."""
        with tempfile.TemporaryDirectory() as tmp:
            index = {
                "schema": engine.CORPUS_SCHEMA,
                "entries": [{
                    "fixture_id": "GHOST-001", "class": "C2-EVAL-STORED",
                    "fixture": "negatives/does-not-exist.py", "label": "pass",
                    "typed_negative_for": "R2-EVAL-FAMILY",
                }],
            }
            with open(os.path.join(tmp, "corpus.json"), "w", encoding="utf-8") as f:
                json.dump(index, f)
            receipt = engine.known_answer(tmp)
            self.assertFalse(receipt["all_pass"], "phantom clean for a missing fixture")
            result = receipt["results"][0]
            self.assertFalse(result["pass"])
            self.assertIn("fixture file missing", result["detail"])
            # and a detect-labeled ghost fails the same way
            index["entries"][0].update({"label": "detect", "caught_by": "R2-EVAL-FAMILY"})
            with open(os.path.join(tmp, "corpus.json"), "w", encoding="utf-8") as f:
                json.dump(index, f)
            receipt = engine.known_answer(tmp)
            self.assertFalse(receipt["all_pass"])
            self.assertIn("fixture file missing", receipt["results"][0]["detail"])


if __name__ == "__main__":
    unittest.main()

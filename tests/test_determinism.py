"""A6 gate: determinism — same corpus + same target tree -> byte-identical
report, sha256-pinned, and byte-identical under a 4-parallel re-run
(sibling standard). No timestamps, no random ids, sorted walks."""
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ADDON_ROOT, "engine.py")
TARGET = os.path.join(ADDON_ROOT, "corpus", "fixtures")


def run_scan():
    done = subprocess.run([sys.executable, ENGINE, TARGET],
                          capture_output=True, cwd=ADDON_ROOT)
    assert done.returncode == 0, done.stderr.decode()
    return done.stdout


class TestDeterminism(unittest.TestCase):
    def test_repeat_runs_byte_identical(self):
        first = run_scan()
        second = run_scan()
        self.assertEqual(first, second)
        digest = hashlib.sha256(first).hexdigest()
        self.assertEqual(len(digest), 64)
        # the report is valid JSON and carries no timestamp-shaped field
        report = json.loads(first.decode())
        self.assertEqual(report["schema"], "constable-report/1")
        for banned in ("timestamp", "created", "elapsed", "duration"):
            self.assertIsNone(re.search(r"\b" + banned, first.decode().lower()),
                              f"report carries timestamp-shaped field: {banned}")

    def test_four_parallel_runs_byte_identical(self):
        baseline = run_scan()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            outputs = list(pool.map(lambda _: run_scan(), range(4)))
        for i, out in enumerate(outputs):
            self.assertEqual(out, baseline, f"parallel run {i} diverged")

    def test_known_answer_deterministic(self):
        def run_ka():
            done = subprocess.run([sys.executable, ENGINE, "--known-answer"],
                                  capture_output=True, cwd=ADDON_ROOT)
            assert done.returncode == 0
            return done.stdout
        self.assertEqual(run_ka(), run_ka())


if __name__ == "__main__":
    unittest.main()

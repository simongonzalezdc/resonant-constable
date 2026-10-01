"""A9 gate: the extension path works — the contest substrate is real.

The documented "add a pattern + fixture" flow (README, rules of engagement:
contribution gates A2/A3/A5a) is executed END-TO-END here against a scratch
copy of the gift:

  1. a contributed PATTERN lands as a code change whose regexes are literals
     compiled at load (R7-GOLDEN-EXEC-SYNC, catching node's execSync
     shell-string shape);
  2. a contributed ATTACK FIXTURE (label detect, caught_by R7) and a typed
     NEGATIVE (label pass) join the corpus index;
  3. the coverage matrix (corpus/MATRIX.md) gains the row;
  4. the checker re-runs the known answer over the EXTENDED corpus: green,
     with the new attack caught and the new negative clean;
  5. the A5a gate passes on the EXTENDED engine (literal-regex-only held).
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ADDON_ROOT, "engine.py")

GOLDEN_ATTACK = '''// G-EXEC-001 — golden contributed attack fixture, class
// C7-GOLDEN-EXEC-SYNC (CWE-78). execSync builds a shell command from stored
// content. Expected label: detect (R7-GOLDEN-EXEC-SYNC).
const { execSync } = require("node:child_process");

function runStep(step) {
  return execSync("npm run " + step);
}
'''

GOLDEN_NEGATIVE = '''// G-EXEC-N001 — golden typed negative for R7-GOLDEN-EXEC-SYNC
// (class C7-GOLDEN-EXEC-SYNC). argv form, no shell. Expected label: pass.
const { execFileSync } = require("node:child_process");

function runStep(step) {
  return execFileSync("npm", ["run", step]);
}
'''

GOLDEN_RULE_BLOCK = '''

# --- contributed pattern: golden extension example (README, rules of
# engagement). A contributed pattern is a reviewed code change; its regexes
# are literals compiled at load, per the A5a contribution gate.
RULES = RULES + (
    _rule(
        "R7-GOLDEN-EXEC-SYNC", "P2-shell-string",
        (re.compile(r"\\bexecSync\\s*\\("),),
        "A synchronous shell runner receives a command assembled from stored content; the shell parses the data as grammar.",
        "Pass an argv array through a shell-less runner (execFileSync or the argv form), or refuse the value against a fixed grammar.",
        "CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html",
    ),
)
RULES_BY_ID = {r["id"]: r for r in RULES}
'''

GOLDEN_MATRIX_ROW = ("| P2-shell-string | R7-GOLDEN-EXEC-SYNC | C7-GOLDEN-EXEC-SYNC "
                     "| G-EXEC-001 | G-EXEC-N001 | — |")


class TestGoldenExtension(unittest.TestCase):
    def test_golden_flow_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "constable")
            os.makedirs(root)
            shutil.copy(ENGINE, os.path.join(root, "engine.py"))
            shutil.copytree(os.path.join(ADDON_ROOT, "corpus"), os.path.join(root, "corpus"))

            # (1) the contributed pattern lands as a code change — inserted
            # before the entrypoint guard, exactly where a reviewed PR puts it
            with open(ENGINE, encoding="utf-8") as f:
                src = f.read()
            marker = 'if __name__ == "__main__":'
            self.assertIn(marker, src)
            src = src.replace(marker, GOLDEN_RULE_BLOCK + "\n\n" + marker, 1)
            with open(os.path.join(root, "engine.py"), "w", encoding="utf-8") as f:
                f.write(src)

            # (2) fixtures join the corpus
            with open(os.path.join(root, "corpus", "fixtures", "attacks", "golden-exec-sync.js"),
                      "w", encoding="utf-8") as f:
                f.write(GOLDEN_ATTACK)
            with open(os.path.join(root, "corpus", "fixtures", "negatives", "golden-neg-execfile.js"),
                      "w", encoding="utf-8") as f:
                f.write(GOLDEN_NEGATIVE)

            index_path = os.path.join(root, "corpus", "corpus.json")
            with open(index_path, encoding="utf-8") as f:
                index = json.load(f)
            index["classes"].append({
                "id": "C7-GOLDEN-EXEC-SYNC",
                "name": "synchronous shell runner fed a built command string",
                "citation": "CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html",
                "doctrine_pattern": "P2-shell-string",
                "rule_id": "R7-GOLDEN-EXEC-SYNC",
                "provenance": "textbook family; contributed via the golden example flow",
            })
            index["entries"].append({
                "fixture_id": "G-EXEC-001", "class": "C7-GOLDEN-EXEC-SYNC",
                "fixture": "attacks/golden-exec-sync.js", "label": "detect",
                "caught_by": "R7-GOLDEN-EXEC-SYNC",
            })
            index["entries"].append({
                "fixture_id": "G-EXEC-N001", "class": "C7-GOLDEN-EXEC-SYNC",
                "fixture": "negatives/golden-neg-execfile.js", "label": "pass",
                "typed_negative_for": "R7-GOLDEN-EXEC-SYNC",
                "lookalike_note": "argv form via execFileSync",
            })
            with open(index_path, "w", encoding="utf-8") as f:
                json.dump(index, f, indent=2, sort_keys=False)

            # (3) the matrix gains the row
            with open(os.path.join(root, "corpus", "MATRIX.md"), "a", encoding="utf-8") as f:
                f.write(GOLDEN_MATRIX_ROW + "\n")

            # (4) the checker re-runs known answer over the EXTENDED corpus: green
            done = subprocess.run([sys.executable, os.path.join(root, "engine.py"),
                                   "--known-answer"], capture_output=True)
            self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
            receipt = json.loads(done.stdout.decode())
            self.assertTrue(receipt["all_pass"])
            self.assertEqual(receipt["attacks_total"], 14)
            self.assertEqual(receipt["negatives_total"], 13)
            golden = next(r for r in receipt["results"] if r["fixture_id"] == "G-EXEC-001")
            self.assertTrue(golden["pass"])
            self.assertIn("R7-GOLDEN-EXEC-SYNC", golden["detail"])
            golden_neg = next(r for r in receipt["results"] if r["fixture_id"] == "G-EXEC-N001")
            self.assertEqual(golden_neg["detail"], "clean")

            # the new rule also fires under the plain scan surface
            scan = subprocess.run([sys.executable, os.path.join(root, "engine.py"),
                                   os.path.join(root, "corpus", "fixtures", "attacks",
                                                "golden-exec-sync.js"), "--text"],
                                  capture_output=True)
            self.assertIn("R7-GOLDEN-EXEC-SYNC", scan.stdout.decode())

            # (5) the A5a gate holds on the EXTENDED engine
            with open(os.path.join(root, "engine.py"), "rb") as f:
                src = f.read()
            tree = ast.parse(src.decode("utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and node.func.attr == "compile" and isinstance(node.func.value, ast.Name) \
                        and node.func.value.id == "re":
                    self.assertIsInstance(node.args[0], ast.Constant,
                                          "extended engine broke literal-regex-only")

    def test_shipped_tree_unchanged_by_golden(self):
        """The golden flow runs on a scratch copy; the shipped corpus stays 27 entries."""
        with open(os.path.join(ADDON_ROOT, "corpus", "corpus.json"), encoding="utf-8") as f:
            index = json.load(f)
        self.assertEqual(len(index["entries"]), 27)
        self.assertEqual(len(index["classes"]), 6)
        with open(ENGINE, encoding="utf-8") as f:
            self.assertNotIn("R7-GOLDEN-EXEC-SYNC", f.read())


if __name__ == "__main__":
    unittest.main()

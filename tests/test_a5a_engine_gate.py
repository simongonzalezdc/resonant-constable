"""A5a gate: engine prohibition — mechanical, automated, build-failing.

The shipped engine (engine.py) and service (server.py) must:
  - import nothing from the process-execution surface (no subprocess, no
    os.system/os.popen, no dynamic code construction: eval/exec/compile/
    __import__ builtins, no globals/locals/setattr-based dispatch);
  - call re.compile ONLY on literal arguments (AST-verified) — a
    contributor shipping a catastrophic-backtracking pattern cannot make
    the checker compile it;
  - open every file in BINARY mode — scanned files are read as opaque
    bytes, never parsed as grammar.

Mechanism: the source is tokenized with string literals STRIPPED (so rule
signatures and prose cannot false-positive), then the code stream is
grepped for the banned shapes; an AST pass enforces the call-level rules.
"""
import ast
import io
import os
import re
import sys
import tokenize
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)

GATED_FILES = ("engine.py", "server.py")

BANNED_SUBSTRINGS = ("subprocess", "__import__", "importlib")
BANNED_DOTTED_RE = (
    r"\bos\s*\.\s*system\b",
    r"\bos\s*\.\s*popen\b",
    r"\bos\s*\.\s*spawn",
    r"\bos\s*\.\s*execv?",
)

BANNED_BUILTIN_CALLS = {"eval", "exec", "compile", "__import__", "globals", "locals", "setattr", "getattr"}


def code_stream(path):
    """Tokenize and drop STRING/COMMENT tokens: what remains is code only."""
    with open(path, "rb") as f:
        raw = f.read()
    out = []
    for tok in tokenize.tokenize(io.BytesIO(raw).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT, tokenize.ENCODING):
            continue
        out.append(tok.string)
    return " ".join(out)


class TestA5aEngineGate(unittest.TestCase):
    def _code(self, name):
        return code_stream(os.path.join(ADDON_ROOT, name))

    def _ast(self, name):
        with open(os.path.join(ADDON_ROOT, name), "rb") as f:
            return ast.parse(f.read().decode("utf-8"), filename=name)

    def test_no_execution_surface_in_code_stream(self):
        for name in GATED_FILES:
            code = self._code(name)
            for banned in BANNED_SUBSTRINGS:
                self.assertNotIn(banned, code,
                                 f"{name}: banned execution surface {banned!r} in code (strings stripped)")
            for pattern in BANNED_DOTTED_RE:
                self.assertIsNone(re.search(pattern, code),
                                  f"{name}: banned call shape {pattern!r} in code (strings stripped)")

    def test_no_dynamic_code_builtin_calls(self):
        for name in GATED_FILES:
            for node in ast.walk(self._ast(name)):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        self.assertNotIn(func.id, BANNED_BUILTIN_CALLS,
                                         f"{name}:{node.lineno}: dynamic builtin call {func.id}()")
                    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                        dotted = f"{func.value.id}.{func.attr}"
                        self.assertNotIn(dotted, ("os.system", "os.popen", "os.execv", "os.spawnl"),
                                         f"{name}:{node.lineno}: banned call {dotted}")

    def test_re_compile_only_on_literal_arguments(self):
        for name in GATED_FILES:
            for node in ast.walk(self._ast(name)):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and node.func.attr == "compile" and isinstance(node.func.value, ast.Name) \
                        and node.func.value.id == "re":
                    self.assertTrue(node.args, f"{name}:{node.lineno}: re.compile with no argument")
                    first = node.args[0]
                    self.assertIsInstance(first, ast.Constant,
                                          f"{name}:{node.lineno}: re.compile on a NON-LITERAL argument")
                    self.assertIsInstance(first.value, str,
                                          f"{name}:{node.lineno}: re.compile pattern is not a string literal")

    def test_every_open_is_binary_opaque_bytes(self):
        for name in GATED_FILES:
            for node in ast.walk(self._ast(name)):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                    modes = [a.value for a in node.args[1:] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                    self.assertTrue(modes, f"{name}:{node.lineno}: open() without an explicit mode")
                    for mode in modes:
                        self.assertIn("b", mode,
                                      f"{name}:{node.lineno}: open() not in binary mode — fixtures must be read as opaque bytes")

    def test_stdlib_only_imports(self):
        # stat: read-only file-mode metadata for the S_ISREG guard (A5b S-2);
        # no execution surface — the banned set below is unchanged.
        allowed = {
            "engine.py": {"argparse", "hashlib", "json", "os", "re", "stat", "sys"},
            "server.py": {"json", "os", "socket", "sys", "engine",
                          "http.server"} | {"http"},
        }
        for name in GATED_FILES:
            for node in ast.walk(self._ast(name)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        self.assertIn(root, allowed[name] | {"http"},
                                      f"{name}: non-stdlib or undeclared import: {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    self.assertIn(root, allowed[name] | {"http"},
                                  f"{name}: non-stdlib or undeclared import: {node.module}")


if __name__ == "__main__":
    unittest.main()

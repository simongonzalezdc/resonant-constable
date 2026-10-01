"""A3 gate: synthetic-only, mechanized — a build-failing test.

Proves the gift content contains zero paths, hostnames, domains, or
token-shaped literals drawn from any live deployment. Three named
mechanisms, all allowlist-driven (nothing is gated on judgment or on the
word "resembles"):

  (i)   absolute-path scan: every absolute-path token must fall under an
        ALLOWLIST path-prefix (synthetic fixtures live under /tmp/);
  (ii)  domain scan: URL hosts and hostname-shaped tokens must suffix-match
        the ALLOWLIST domain set; high-entropy tokens (hex >= 16, and any
        provider-token shape) must be allowlisted (none are);
  (iii) citation gate: PR-shaped, issue-shaped, short/long commit-sha-shaped,
        and their-tree path-shaped citations must be members of the
        ALLOWLIST citation set (merged fixes PR 333 + ADR-034 + public docs
        + our own origin bugs). Anything cited outside it fails the build.

Scan scope: corpus/, docs/, README.md, PROCEDURE.md, ALLOWLIST-excluded
nothing — the whole shipped voice of the gift.
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)

SCAN_ROOTS = ("corpus", "docs")
SCAN_FILES = ("README.md", "PROCEDURE.md")

TLD_SET = ("com", "org", "net", "io", "dev", "tech", "app", "ai", "co")


def parse_allowlist():
    sections = {}
    current = None
    with open(os.path.join(ADDON_ROOT, "ALLOWLIST"), encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                sections[current] = []
                continue
            if current:
                sections[current].append(line.lower())
    return sections


ALLOW = parse_allowlist()

# token shapes (URL_RE consumes the WHOLE url, path included)
URL_RE = re.compile(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s()<>`\"']*)?")
ABSPATH_RE = re.compile(r"(?<![\w])/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+")
HOSTNAME_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9-]+\.)+(?:%s))\b" % "|".join(TLD_SET))
HEX_RE = re.compile(r"\b[0-9a-f]{16,64}\b")
PROVIDER_TOKEN_RE = re.compile(r"\b(?:sk|ghp|gho|ghu|github_pat|xoxb|xoxp)[-_][A-Za-z0-9_-]{16,}\b")
PR_RE = re.compile(r"\bPR\s?#?(\d+)\b")
ISSUE_RE = re.compile(r"\bissue\s+#?(\d+)\b", re.IGNORECASE)
SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
THEIRPATH_RE = re.compile(r"\b((?:scripts|src|packages)/[A-Za-z0-9_./-]+|docs/architecture/[A-Za-z0-9_./-]+)")


def scan_texts():
    texts = {}
    for root in SCAN_ROOTS:
        for dirpath, dirs, names in os.walk(os.path.join(ADDON_ROOT, root)):
            dirs[:] = sorted(dirs)
            for name in sorted(names):
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, ADDON_ROOT)
                with open(path, "rb") as f:
                    texts[rel] = f.read().decode("utf-8", errors="replace")
    for name in SCAN_FILES:
        path = os.path.join(ADDON_ROOT, name)
        with open(path, "rb") as f:
            texts[name] = f.read().decode("utf-8", errors="replace")
    return texts


class TestA3SyntheticOnly(unittest.TestCase):
    """Every check names its mechanism; every allowed value lives in ALLOWLIST."""

    @classmethod
    def setUpClass(cls):
        cls.texts = scan_texts()

    def _failures(self, check):
        bad = []
        for rel, text in self.texts.items():
            for hit in check(text):
                bad.append((rel, hit))
        return bad

    def test_i_all_absolute_paths_are_allowlisted_prefixes(self):
        prefixes = tuple(ALLOW["path-prefixes"])

        def check(text):
            stripped = URL_RE.sub("", text)  # URL paths are the domain check's job
            for m in ABSPATH_RE.finditer(stripped):
                tok = m.group(0)
                if not tok.lower().startswith(prefixes):
                    yield tok
        failures = self._failures(check)
        self.assertEqual(failures, [], "absolute paths outside ALLOWLIST prefixes")

    def test_ii_all_domains_are_allowlisted(self):
        allowed = tuple(ALLOW["domains"])

        def host_allowed(host):
            return any(host == d or host.endswith("." + d) for d in allowed)

        def check(text):
            for m in re.finditer(r"https?://([A-Za-z0-9.-]+)(?::\d+)?", text):
                host = m.group(1).lower()
                if not host_allowed(host):
                    yield "url-host:" + host
            stripped = URL_RE.sub("", text)
            for m in HOSTNAME_RE.finditer(stripped):
                host = m.group(1).lower()
                if not host_allowed(host):
                    yield host
        failures = self._failures(check)
        self.assertEqual(failures, [], "domains outside the ALLOWLIST")

    def test_ii_no_high_entropy_or_provider_token_shapes(self):
        exemptions = set(ALLOW.get("entropy-exemptions", []))

        def check(text):
            for m in HEX_RE.finditer(text):
                if m.group(0) not in exemptions:
                    yield "hex-token:" + m.group(0)[:12] + "..."
            for m in PROVIDER_TOKEN_RE.finditer(text):
                yield "provider-token:" + m.group(0)[:12] + "..."
        failures = self._failures(check)
        self.assertEqual(failures, [], "token-shaped literals outside the entropy-exemption set")

    def test_iii_code_citations_restricted_to_the_citation_allowlist(self):
        allowed_prs = {"333"}
        allowed_issues = {"163"}
        allowed_shas = {t for t in set(ALLOW["citations"]) | set(ALLOW.get("entropy-exemptions", [])) | set(ALLOW["own-origin"])
                        if re.fullmatch(r"[0-9a-f]{7,40}", t)}
        allowed_paths = set(ALLOW["citations"]) | set(ALLOW["own-origin"])

        def check(text):
            for m in PR_RE.finditer(text):
                if m.group(1) not in allowed_prs:
                    yield "PR " + m.group(1)
            for m in ISSUE_RE.finditer(text):
                if m.group(1) not in allowed_issues:
                    yield "issue #" + m.group(1)
            for m in SHA_RE.finditer(text):
                if m.group(0) not in allowed_shas:
                    yield "sha:" + m.group(0)
            for m in THEIRPATH_RE.finditer(text):
                tok = m.group(1).rstrip(".,;:`)")
                if tok.lower() not in allowed_paths:
                    yield "their-path:" + tok
        failures = self._failures(check)
        self.assertEqual(failures, [], "citations outside the ALLOWLIST (merged fixes + public docs + our origin bugs only)")

    def test_gate_covers_the_whole_shipped_voice(self):
        self.assertIn("corpus/corpus.json", self.texts)
        self.assertIn("docs/DOCTRINE.md", self.texts)
        self.assertIn("README.md", self.texts)
        self.assertGreaterEqual(len(self.texts), 20)


if __name__ == "__main__":
    unittest.main()

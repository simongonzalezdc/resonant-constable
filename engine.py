#!/usr/bin/env python3
"""addon.constable — the injection-defense reference checker (stdlib only).

One job: point the checker at an add-on or script tree the OPERATOR chose and
get a deterministic, detect-and-explain report of known injection-construction
sites. It is a teaching lint for add-on authors, not an audit: conservative
default is report-and-continue (exit 0 even with findings); --strict is the
operator's explicit opt-in to a nonzero exit.

Doctrine (docs/DOCTRINE.md): stored content is never interpolated into shell
strings; parse as data; adversarial QA is the gate that catches what review
misses. Each rule below names its doctrine pattern and its public attack
class, and every rule carries the data-boundary alternative in its fix hint.

Hard properties (test-pinned, tests/test_a5a_engine_gate.py):
  - stdlib only; no subprocess, no os.system/os.popen, no eval/exec of
    dynamic text, no dynamic code construction anywhere;
  - every detection pattern is a LITERAL regex compiled once at module load
    (never re.compile on data, never on contributor input) — a contributor
    cannot hand the checker a catastrophic pattern and self-DoS it;
  - scanned files are read as OPAQUE BYTES and decoded leniently for
    line-wise matching; the engine never parses a scanned file as grammar;
  - only REGULAR files are ever opened (stat.S_ISREG before every open):
    FIFOs, devices, and symlink loops in a scanned tree (or in the corpus
    tree) are skipped and counted loudly — never a hang, never a traceback;
  - corpus fixture paths are strictly contained: absolute paths, '..'
    traversal, and symlinks escaping corpus/fixtures are rejected with a
    named reason, by the engine and by the A2 integrity gate alike; a
    fixture that does not exist is a named known-answer failure, never a
    phantom "clean" negative (A5b round-2 F-6a);
  - the text report escapes control characters (C0, DEL, the C1 range) and
    the Unicode line separators / RTL override / zero-width characters in
    scanned-data strings (paths, excerpts), so a hostile filename cannot
    forge report lines on any terminal (A5b S-1; round-2 F-1);
  - every corpus read is size-bounded: the hash and the index parse cap
    per-file reads at MAX_FILE_BYTES (A5b round-2 F-4), the hash frames
    each record with its length so splices cannot collide (round-2 F-8),
    and findings are capped per file and per report with an honest
    suppressed count (round-2 F-5);
  - deterministic: sorted walk, sorted findings, no timestamps, no random
    ids — same corpus + same target tree gives byte-identical reports.

Known answer (A4): with --known-answer the engine runs the pinned corpus and
verifies every fixture against its label. Because corpus and checker are
co-developed, this proves the checker executes its own labels; it is NOT an
efficacy claim against the world.

Redaction law (A8): paths are reported as the operator gave them with the
home directory shown as "~"; findings quote a minimal excerpt (at most 160
characters around the match), never a whole file; stdout log lines carry no
scanned content at all.

Surfaces: importable functions (scan_path, known_answer, ...) and a CLI.
No network, no subprocess, no writes unless --out is given (then exactly one
report file). Exit codes: 0 report produced (or known answer 100%); 2
--strict and findings exist, or known answer < 100%; 78 never (that is the
service's bind-conflict code); usage errors exit 2 with a message on stderr.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys

ENGINE_VERSION = "0.1.0"
REPORT_SCHEMA = "constable-report/1"
CORPUS_SCHEMA = "constable-corpus/1"

# The receipt banner — pinned verbatim by tests/test_docs_pins.py and
# carried on every report and known-answer receipt.
RECEIPT_BANNER = (
    "This kit teaches a defense discipline and ships a reference checker. "
    "It claims nothing about the security of any deployed ResonantOS system. "
    "All corpus entries are public attack classes demonstrated on synthetic "
    "fixtures. This is not a security audit."
)
KNOWN_ANSWER_NOTE = (
    "known-answer rehearsal — corpus and checker are co-developed, so this "
    "run proves the checker executes its own labels; it is not an efficacy "
    "claim against the world"
)

MAX_FILE_BYTES = 8 * 1024 * 1024      # refuse to slurp anything huge
MAX_FILES = 4096                      # refuse to walk a monster tree
MAX_EXCERPT = 160                     # minimal-span redaction law
MAX_INDEX_BYTES = MAX_FILE_BYTES      # corpus.json parse bound (A5b-r2 F-4)
MAX_FINDINGS_PER_FILE = 500           # per-file findings cap (A5b-r2 F-5)
MAX_FINDINGS = 1000                   # per-report findings cap (A5b-r2 F-5)
DEFAULT_EXTENSIONS = (
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".zsh",
)

# --------------------------------------------------------------- the rules
# Every pattern below is compiled ONCE, here, from a LITERAL argument at
# module load — the A5a gate (tests/test_a5a_engine_gate.py) enforces by AST
# that no re.compile anywhere takes a non-literal, so a contributor cannot
# hand the checker a dynamic or catastrophic pattern. The fix hints carry
# the doctrine's data-boundary alternative. Citations are public.

R1_SHELL_STRING_EXEC = (
    re.compile(r"\bos\.(?:system|popen)\s*\("),
    re.compile(r"\bsubprocess\.(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(\s*f[\"']"),
    re.compile(r"shell\s*=\s*True"),
    re.compile(r"shell\s*:\s*true\b"),
    re.compile(r"\bspawnSync\s*\(\s*[\"'`]"),
    re.compile(r"\bchild_process\s*\.\s*exec\s*\("),
    re.compile(r"\bexec\s*\(\s*[\"'`][^\"'`]*\$\{"),
)
R2_EVAL_FAMILY = (
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bawk\b[^|;\n]*\bsystem\s*\("),
)
R3_LOOSE_KEY_PARSE = (
    re.compile(r"\.split\s*\(\s*[\"'][A-Za-z_][A-Za-z0-9_-]*[\"']\s*\)\s*\[\s*(?:1|-1)\s*\]"),
    re.compile(r"\.find\s*\(\s*[\"'][A-Za-z_][A-Za-z0-9_:-]*[\"']\s*\)\s*\+"),
    re.compile(r"\.indexOf\s*\(\s*[\"'][A-Za-z_][A-Za-z0-9_-]*[\"']\s*\)\s*\+"),
)
R4_REGEX_INTERPOLATION = (
    re.compile(r"\bre\.(?:compile|search|match|fullmatch|sub|split)\s*\(\s*f[\"']"),
    re.compile(r"\bre\.compile\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
    re.compile(r"\bnew\s+RegExp\s*\(\s*[A-Za-z_$]"),
)
R5_INSTRUCTION_CONCAT = (
    re.compile(r"[\"'][^\"'\n]{0,200}(?:system:|instructions?:|ignore\s+(?:all\s+)?previous)[^\"'\n]{0,200}[\"']\s*\+", re.IGNORECASE),
)
R6_CATASTROPHIC_QUANTIFIER = (
    re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]"),
)


def _rule(rule_id, doctrine_pattern, patterns, explanation, fix_hint, citation):
    return {
        "id": rule_id,
        "doctrine_pattern": doctrine_pattern,
        "patterns": list(patterns),
        "explanation": explanation,
        "fix_hint": fix_hint,
        "citation": citation,
    }


RULES = (
    _rule(
        "R1-SHELL-STRING-EXEC", "P2-shell-string", R1_SHELL_STRING_EXEC,
        "A command string is built by interpolation (or handed to a shell) where stored content can reach it; whatever the string contains, the shell will parse as grammar.",
        "Kill the string: pass an argv array and shell=False, so the boundary parses arguments as data (quote-aware splitter at most, never a shell).",
        "CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html",
    ),
    _rule(
        "R2-EVAL-FAMILY", "P2-shell-string", R2_EVAL_FAMILY,
        "Stored text is handed to a dynamic evaluator (or to awk's system(), which evaluates a shell string per record); the data becomes a program.",
        "Never evaluate stored content: dispatch through a fixed table of functions, or parse the value with a fixed grammar and compare against known constants.",
        "CWE-95: Eval Injection — https://cwe.mitre.org/data/definitions/95.html",
    ),
    _rule(
        "R3-LOOSE-KEY-PARSE", "P3-loose-grammar", R3_LOOSE_KEY_PARSE,
        "A keyed record is parsed by finding a bare keyword and taking whatever follows — first-match wins, so a forged keyword inside stored content wins the parse.",
        "Parse as data: split on a full field delimiter (key + separator, e.g. \"cutoff: \"), validate the field against a fixed grammar, and refuse what does not match.",
        "CWE-20: Improper Input Validation — https://cwe.mitre.org/data/definitions/20.html",
    ),
    _rule(
        "R4-REGEX-INTERPOLATION", "P4-regex-interpolation", R4_REGEX_INTERPOLATION,
        "A regular expression (or query grammar) is assembled from stored text, so metacharacters in the data change what the pattern matches.",
        "Match against pre-built literal patterns only; if the key must vary, escape it with a quoting function or refuse non-conforming keys before they reach the grammar.",
        "CWE-185: Incorrect Regular Expression — https://cwe.mitre.org/data/definitions/185.html",
    ),
    _rule(
        "R5-INSTRUCTION-CONCAT", "P1-message-boundary", R5_INSTRUCTION_CONCAT,
        "Stored content is concatenated straight into instruction-bearing text; the boundary between operator instructions and stored data is one the data can rewrite.",
        "Carry stored content across a structured boundary: a fenced, labeled section the grammar defines (join or template), never raw concatenation into instruction text.",
        "OWASP Top 10 for LLM Applications, LLM01: Prompt Injection — https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    _rule(
        "R6-CATASTROPHIC-QUANTIFIER", "P4-regex-interpolation", R6_CATASTROPHIC_QUANTIFIER,
        "A quantified group containing its own quantifier (nested quantifiers) can backtrack exponentially on adversarial input — a denial-of-service in one line.",
        "Anchor the alternation, bound the repetition, or linearize the pattern; every contributed checker pattern must be literal-regex-only for exactly this reason.",
        "CWE-1333: Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html",
    ),
)

RULES_BY_ID = {r["id"]: r for r in RULES}


# ------------------------------------------------------------- scanning core
def _redact_home(text):
    home = os.path.expanduser("~")
    return text.replace(home, "~") if home and home != "~" else text


def _needs_report_escape(ch):
    """A5b round-2 F-1: the report-escape character class. C0 controls, DEL,
    the whole C1 range 0x7F-0x9F (U+009B is a live CSI introducer and U+0085
    a line break on C1-honoring terminals), the Unicode line/paragraph
    separators U+2028/U+2029, the RTL override U+202E, and the zero-width
    space U+200B."""
    o = ord(ch)
    return o < 0x20 or 0x7F <= o <= 0x9F or ch in "\u2028\u2029\u202e\u200b"


def _escape_report_text(text):
    """Text-report safety (A5b S-1; round-2 F-1 extends the class): control
    characters — newlines, ANSI escapes, NUL, DEL, the C1 range — and the
    Unicode line separators / RTL override / zero-width characters in
    scanned-data strings become \\uXXXX so a hostile filename or file line
    cannot forge report lines or inject terminal escapes into the
    human-readable output, on ANY terminal, not only C1-inert ones. JSON
    mode needs no help: ensure_ascii escaping already covers these."""
    if not any(_needs_report_escape(ch) for ch in text):
        return text
    return "".join(
        "\\u%04x" % ord(ch) if _needs_report_escape(ch) else ch
        for ch in text
    )


def _readable_regular(path):
    """True only for paths that stat cleanly AND are regular files (A5b S-2):
    FIFOs, device files, and symlink loops are never opened — a hostile tree
    degrades to a loudly skipped entry, never a hang or a traceback."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def _excerpt(line, start, end):
    """Minimal-span quote: the matched line trimmed to MAX_EXCERPT chars
    around the match, with ellipses where content was cut. Never a whole
    file; never a whole long line."""
    if len(line) <= MAX_EXCERPT:
        return line
    pad = (MAX_EXCERPT - (end - start)) // 2
    lo = max(0, start - pad)
    hi = min(len(line), end + pad)
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(line) else ""
    return prefix + line[lo:hi] + suffix


def _iter_target_files(path, extensions):
    """Operator-given roots only (A7): no discovery beyond what was passed.
    A directory walk filters by extension and respects the size/count caps;
    a single explicitly passed target is yielded whatever it is — regularity
    is enforced by the caller, so non-regular targets (FIFOs, devices,
    dangling links) are skipped and counted, never opened (A5b S-2)."""
    if os.path.isdir(path):
        count = 0
        for root, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in (".git", "__pycache__", "node_modules"))
            for name in sorted(names):
                if count >= MAX_FILES:
                    return
                if os.path.splitext(name)[1].lower() in extensions:
                    count += 1
                    yield os.path.join(root, name)
        return
    if os.path.lexists(path):
        yield path


def _scan_file_limited(abs_path, rule_ids=None, limit=MAX_FINDINGS_PER_FILE):
    """The scanning core of scan_file, reporting (findings, suppressed):
    `suppressed` counts rule matches beyond `limit` (A5b round-2 F-5) so the
    caller can report truncation honestly instead of amplifying memory — a
    file of thousands of matching lines previously produced one finding dict
    per match (649 MB RSS from a single 8 MB-capped file in the round-2
    battery)."""
    if not _readable_regular(abs_path):
        return [], 0
    try:
        with open(abs_path, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        # lost the stat/open race, ELOOP, or an unreadable file: skip, never
        # crash or block — a hostile tree cannot take the engine down
        return [], 0
    if len(raw) > MAX_FILE_BYTES:
        raw = raw[:MAX_FILE_BYTES]
    text = raw.decode("utf-8", errors="replace")
    findings = []
    suppressed = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if rule_ids and rule["id"] not in rule_ids:
                continue
            for pattern in rule["patterns"]:
                match = pattern.search(line)
                if match is None:
                    continue
                if len(findings) >= limit:
                    suppressed += 1
                else:
                    findings.append({
                        "rule_id": rule["id"],
                        "doctrine_pattern": rule["doctrine_pattern"],
                        "path": _redact_home(abs_path),
                        "line": lineno,
                        "excerpt": _redact_home(_excerpt(line, match.start(), match.end())),
                        "explanation": rule["explanation"],
                        "fix_hint": rule["fix_hint"],
                        "citation": rule["citation"],
                    })
                break  # one finding per line per rule: minimal quoting
    return findings, suppressed


def scan_file(abs_path, rule_ids=None):
    """Read one file as OPAQUE BYTES, decode leniently, and return findings.
    The bytes are never parsed as grammar by this engine — every line is
    matched only against the pre-built literal rule patterns. Non-regular
    files (FIFOs, devices, symlink loops) are never opened (A5b S-2): they
    yield no findings and the caller counts them as skipped. Findings are
    capped per file at MAX_FINDINGS_PER_FILE (A5b round-2 F-5); the
    per-report cap and the honest suppressed count live in scan_paths."""
    findings, _suppressed = _scan_file_limited(abs_path, rule_ids)
    return findings


def scan_paths(paths, extensions=DEFAULT_EXTENSIONS):
    """Scan operator-given roots. Returns (findings, files_scanned,
    files_skipped, findings_suppressed): files_skipped counts entries in the
    scanned trees that were never opened because they are not regular files
    (or vanished) — reported loudly in both output modes, never silently
    (A5b S-2). findings_suppressed counts rule matches dropped by the
    per-file cap (MAX_FINDINGS_PER_FILE) and the per-report cap
    (MAX_FINDINGS) so a findings-amplification file degrades to a bounded,
    honestly-labeled report instead of unbounded memory (A5b round-2 F-5).
    Sorted walk, sorted findings — byte-identical input gives byte-identical
    output."""
    findings = []
    files_scanned = 0
    files_skipped = 0
    findings_suppressed = 0
    for given in paths:
        for abs_path in _iter_target_files(given, extensions):
            if _readable_regular(abs_path):
                files_scanned += 1
                file_findings, file_suppressed = _scan_file_limited(abs_path)
                findings_suppressed += file_suppressed
                room = MAX_FINDINGS - len(findings)
                if room <= 0:
                    findings_suppressed += len(file_findings)
                elif len(file_findings) > room:
                    findings.extend(file_findings[:room])
                    findings_suppressed += len(file_findings) - room
                else:
                    findings.extend(file_findings)
            else:
                files_skipped += 1
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule_id"]))
    return findings, files_scanned, files_skipped, findings_suppressed


def build_report(paths, findings, files_scanned, files_skipped=0, findings_suppressed=0):
    """The deterministic report object. No timestamps, no random ids.
    findings_truncated/findings_suppressed (A5b round-2 F-5) name any
    findings-cap truncation honestly in the report itself."""
    rules_fired = sorted({f["rule_id"] for f in findings})
    by_pattern = {}
    for f in findings:
        by_pattern.setdefault(f["doctrine_pattern"], []).append(f["rule_id"])
    return {
        "schema": REPORT_SCHEMA,
        "banner": RECEIPT_BANNER,
        "engine_version": ENGINE_VERSION,
        "mode": "detect-and-explain",
        "targets": [_redact_home(p) for p in paths],
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "findings_count": len(findings),
        "findings_truncated": findings_suppressed > 0,
        "findings_suppressed": findings_suppressed,
        "rules_fired": rules_fired,
        "doctrine_patterns_hit": sorted({k: sorted(set(v)) for k, v in by_pattern.items()}.keys()),
        "findings": findings,
    }


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True).encode("utf-8")


# ------------------------------------------------------------- known answer
def corpus_hash(corpus_dir):
    """sha256 over the full corpus read set, LENGTH-FRAMED per record (A5b
    round-2 F-8): each record contributes b"<len>:<rel>:" plus
    b"<len>:<content>:" so a framing splice cannot collide — under the old
    unframed `rel \\0 content \\0` stream, fixture content carrying
    NUL + a forged relpath + further bytes digested identically to a
    two-fixture corpus (demonstrated round-2; regression-pinned in
    tests/test_corpus_integrity.py). Per-file reads are capped at
    MAX_FILE_BYTES (A5b round-2 F-4): a huge unindexed file under corpus/
    can no longer blow up the reader's memory (the round-2 3 GB sparse file
    drove max RSS to 3.24 GB). Non-regular entries (FIFOs, devices, symlink
    escapes) are never opened — a hostile corpus cannot hang the hash
    (A5b S-2/C4); the A2 corpus-hygiene gate fails the build on such
    entries instead."""
    digest = hashlib.sha256()
    for root, dirs, names in os.walk(corpus_dir):
        dirs[:] = sorted(dirs)
        for name in sorted(names):
            abs_path = os.path.join(root, name)
            if not _readable_regular(abs_path):
                continue
            rel = os.path.relpath(abs_path, corpus_dir).replace(os.sep, "/")
            try:
                with open(abs_path, "rb") as handle:
                    content = handle.read(MAX_FILE_BYTES)
            except OSError:
                continue
            for part in (rel.encode("utf-8"), content):
                digest.update(str(len(part)).encode("ascii") + b":" + part + b":")
    return digest.hexdigest()


def load_corpus(corpus_dir):
    index_path = os.path.join(corpus_dir, "corpus.json")
    with open(index_path, "rb") as handle:
        raw = handle.read(MAX_INDEX_BYTES + 1)
    if len(raw) > MAX_INDEX_BYTES:
        # A5b round-2 F-4: the index parse is size-bounded like every other
        # read — refuse loudly instead of parsing an unbounded blob
        raise SystemExit(
            f"corpus index {index_path}: larger than the "
            f"{MAX_INDEX_BYTES}-byte bound — refusing to parse")
    index = json.loads(raw.decode("utf-8"))
    if index.get("schema") != CORPUS_SCHEMA:
        raise SystemExit(f"corpus index {index_path}: unexpected schema {index.get('schema')!r}")
    return index


def resolve_fixture(fixtures_dir, rel):
    """Resolve a corpus fixture path with STRICT containment (A5b S-3).
    Returns (abs_path, None) on success, or (None, reason) when the path is
    not a clean RELATIVE path that resolves INSIDE fixtures_dir: absolute
    paths, '..' traversal, and symlinks escaping the fixtures root are all
    rejected with a named reason. Both the engine's known-answer run and the
    A2 integrity gate enforce the same rule through this helper, so a hostile
    fixture path can neither be read nor digested into corpus_hash."""
    if not isinstance(rel, str) or not rel.strip():
        return None, "fixture path missing or not a string"
    if os.path.isabs(rel) or rel.startswith("/"):
        return None, "absolute fixture path rejected (must be relative to corpus/fixtures)"
    segments = rel.split("/")
    if any(segment == ".." for segment in segments):
        return None, "'..' traversal rejected (fixture must stay under corpus/fixtures)"
    if any(segment in ("", ".") for segment in segments):
        return None, "malformed fixture path (empty or '.' segment)"
    root = os.path.realpath(fixtures_dir)
    abs_path = os.path.realpath(os.path.join(root, rel))
    if abs_path != root and not abs_path.startswith(root + os.sep):
        return None, "fixture resolves outside corpus/fixtures (symlink escape rejected)"
    return abs_path, None


def known_answer(corpus_dir):
    """Run the pinned corpus against its labels:
      detect -> at least the named rule must fire on the fixture;
      pass   -> no rule may fire;
      reject -> the fixture IS a data-boundary defense exemplar, so no rule
                may fire on it either (the boundary refuses, the lint agrees).
    Returns a receipt dict; exit code is the caller's decision."""
    index = load_corpus(corpus_dir)
    fixtures_dir = os.path.join(corpus_dir, "fixtures")
    results = []
    for entry in index["entries"]:
        rel = entry.get("fixture")
        abs_path, reason = resolve_fixture(fixtures_dir, rel)
        if abs_path is None:
            # containment failure (A5b S-3): report a named failed line and
            # move on — never read outside corpus/fixtures, never crash
            results.append({
                "fixture_id": entry.get("fixture_id"),
                "file": rel if isinstance(rel, str) else repr(rel),
                "class": entry.get("class"),
                "label": entry.get("label"),
                "pass": False,
                "detail": "fixture rejected: " + reason,
            })
            continue
        if not os.path.isfile(abs_path):
            # A5b round-2 F-6a: a contained-but-absent fixture must be a
            # named FAILURE, never a silent phantom "clean" negative (the
            # A2 gate catches this pre-merge; known_answer enforces it too,
            # defense in depth)
            results.append({
                "fixture_id": entry.get("fixture_id"),
                "file": rel,
                "class": entry.get("class"),
                "label": entry.get("label"),
                "pass": False,
                "detail": "fixture file missing: " + rel,
            })
            continue
        fired = sorted({f["rule_id"] for f in scan_file(abs_path)})
        label = entry["label"]
        if label == "detect":
            ok = entry["caught_by"] in fired
            detail = "caught by " + ",".join(fired) if fired else "no rule fired"
        elif label in ("pass", "reject"):
            ok = not fired
            detail = "clean" if not fired else "unexpected: " + ",".join(fired)
        else:
            ok = False
            detail = f"unknown label {label!r}"
        results.append({
            "fixture_id": entry["fixture_id"],
            "file": rel,
            "class": entry["class"],
            "label": label,
            "pass": ok,
            "detail": detail,
        })
    results.sort(key=lambda r: r["fixture_id"])
    attacks = [r for r in results if r["label"] == "detect"]
    negatives = [r for r in results if r["label"] == "pass"]
    defenses = [r for r in results if r["label"] == "reject"]
    return {
        "schema": "constable-known-answer/1",
        "banner": RECEIPT_BANNER,
        "note": KNOWN_ANSWER_NOTE,
        "engine_version": ENGINE_VERSION,
        "corpus_hash": corpus_hash(corpus_dir),
        "all_pass": all(r["pass"] for r in results),
        "attacks_detected": sum(1 for r in attacks if r["pass"]),
        "attacks_total": len(attacks),
        "negatives_clean": sum(1 for r in negatives if r["pass"]),
        "negatives_total": len(negatives),
        "defenses_clean": sum(1 for r in defenses if r["pass"]),
        "defenses_total": len(defenses),
        "results": results,
    }


# --------------------------------------------------------------------- CLI
def _default_corpus_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="engine.py",
        description="Constable injection-defense checker (detect-and-explain).",
    )
    parser.add_argument("paths", nargs="*", help="operator-chosen files or directories to scan")
    parser.add_argument("--known-answer", action="store_true",
                        help="run the pinned corpus against its labels instead of scanning")
    parser.add_argument("--corpus", default=None, help="corpus directory (default: ./corpus beside engine.py)")
    parser.add_argument("--out", default=None, help="write the JSON report to this file (var/ recommended)")
    parser.add_argument("--text", action="store_true", help="human-readable report on stdout")
    parser.add_argument("--strict", action="store_true",
                        help="exit 2 if findings exist (operator opt-in; default never fails the build)")
    args = parser.parse_args(argv)
    corpus_dir = args.corpus or _default_corpus_dir()

    if args.known_answer:
        receipt = known_answer(corpus_dir)
        payload = canonical_bytes(receipt)
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "wb") as handle:
                handle.write(payload)
            sys.stdout.write("constable: known-answer receipt written to " + _redact_home(args.out) + "\n")
        else:
            sys.stdout.write(payload.decode("utf-8") + "\n")
        return 0 if receipt["all_pass"] else 2

    if not args.paths:
        parser.error("give at least one path to scan (operator-scoped reads only)")

    findings, files_scanned, files_skipped, findings_suppressed = scan_paths(args.paths)
    report = build_report(args.paths, findings, files_scanned, files_skipped, findings_suppressed)
    payload = canonical_bytes(report)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "wb") as handle:
            handle.write(payload)
        line = ("constable: scanned " + str(files_scanned) + " files, "
                + str(report["findings_count"]) + " findings; report at "
                + _redact_home(args.out))
        if report["findings_truncated"]:
            line += ("; " + str(report["findings_suppressed"])
                     + " further findings suppressed (report cap)")
        sys.stdout.write(line + "\n")
    elif args.text:
        sys.stdout.write("constable report — detect-and-explain\n")
        sys.stdout.write(RECEIPT_BANNER + "\n")
        sys.stdout.write("targets: "
                         + ", ".join(_escape_report_text(t) for t in report["targets"]) + "\n")
        sys.stdout.write("files scanned: " + str(files_scanned) + "\n")
        if files_skipped:
            sys.stdout.write("skipped (not regular files — FIFOs, devices, or dangling/"
                             " looping links — never opened): " + str(files_skipped) + "\n")
        if report["findings_truncated"]:
            sys.stdout.write("findings capped at " + str(MAX_FINDINGS) + " — "
                             + str(report["findings_suppressed"])
                             + " further findings suppressed; narrow the scan for the rest\n")
        sys.stdout.write("\n")
        for f in findings:
            sys.stdout.write(
                _escape_report_text(f["path"]) + ":" + str(f["line"]) + "  [" + f["rule_id"] + "]\n"
                + "  matched: " + _escape_report_text(f["excerpt"]) + "\n"
                + "  why: " + f["explanation"] + "\n"
                + "  fix: " + f["fix_hint"] + "\n"
                + "  class: " + f["citation"] + "\n\n"
            )
        if not findings:
            sys.stdout.write("no known injection-construction sites found\n")
    else:
        sys.stdout.write(payload.decode("utf-8") + "\n")

    if args.strict and findings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

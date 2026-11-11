#!/usr/bin/env python3
"""Python Scanner: static analysis for Python files and projects.

Project code is only read and parsed. It is never imported or executed.

Stage 3 analysis engine:
  * Syntax        built-in, uses the interpreter's own parser (ast)
  * Secrets       built-in, regex + entropy; values are masked before they are stored
  * Dependencies  built-in, compares imports with requirements.txt / pyproject.toml (offline)
  * Ruff          optional external tool (code quality), run as a read-only subprocess
  * Bandit        optional external tool (security patterns), run as a read-only subprocess

Ruff and Bandit are optional. If one is missing or fails, the other analyzers still run.
Optional install:  pip install ruff bandit

Requires Python 3.9+ and Kivy 2.2+. Designed for Android/Pydroid 3.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import math
import os
import queue
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import traceback
import warnings
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import (Callable, Dict, FrozenSet, Iterator, List, Optional, Sequence,
                    Set, Tuple)

APP_TITLE = "Python Scanner Neon"
APP_VERSION = "2.0.0"
DEFAULT_IGNORED_DIRS = (
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "build", "dist", "site-packages", ".idea", ".vscode",
    "*.egg-info",
)
DEFAULT_MAX_FILE_MB = 2
MAX_FILE_MB_LIMIT = 64
DISCOVERY_PROGRESS_STEP = 100
POLL_INTERVAL_MS = 80
MAX_EVENTS_PER_TICK = 200
SHUTDOWN_GRACE_MS = 3000
SNIPPET_MAX_CHARS = 200

# External tools
DEFAULT_TOOL_TIMEOUT = 120      # seconds per tool invocation (one chunk of files)
TOOL_VERSION_TIMEOUT = 20       # seconds for the "--version" probe
TOOL_CHUNK_FILES = 150          # max files per tool invocation
TOOL_CHUNK_CHARS = 24000        # max total length of path arguments per invocation
PROJECT_LABEL = "(project)"     # "file" used by findings that concern the whole scan

# Secret scanner
MAX_SECRET_LINE_CHARS = 4000    # longer lines are truncated before regex matching
MAX_MANIFEST_BYTES = 1024 * 1024

Emit = Callable[[str, object], None]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Category(Enum):
    SYNTAX = "syntax"
    QUALITY = "quality"
    SECURITY = "security"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    SCAN = "scan"  # problems with the scan itself, not with the analyzed code


class Confidence(Enum):
    DEFINITE = "definite"   # certain (for example a syntax error)
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    POSSIBLE = "possible"   # a hint that may be wrong (dependency checks)


class ScanStatus(Enum):
    COMPLETED = "completed"
    COMPLETED_WITH_ISSUES = "completed with issues"
    CANCELLED = "cancelled"


class ToolState(Enum):
    OK = "ok"
    MISSING = "not installed"
    FAILED = "failed"
    TIMEOUT = "timed out"
    SKIPPED = "not run"


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: Severity
    category: Category
    confidence: Confidence
    file: str
    line: Optional[int]
    message: str
    snippet: Optional[str] = None


@dataclass(frozen=True)
class ToolStatus:
    name: str
    builtin: bool
    state: ToolState
    version: str = ""
    detail: str = ""


@dataclass
class ScanConfig:
    target: Path
    recursive: bool = True
    ignored_dirs: Tuple[str, ...] = DEFAULT_IGNORED_DIRS
    max_file_size: int = DEFAULT_MAX_FILE_MB * 1024 * 1024
    tool_timeout: int = DEFAULT_TOOL_TIMEOUT


@dataclass
class DiscoveredFile:
    path: Path
    display: str
    size: int


@dataclass
class DiscoveryResult:
    files: List[DiscoveredFile] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    cancelled: bool = False


@dataclass
class ScanResult:
    target: Path
    analyzers: List[str]
    started_at: str
    status: ScanStatus = ScanStatus.COMPLETED
    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0
    duplicates_removed: int = 0
    findings: List[Finding] = field(default_factory=list)
    tool_statuses: List[ToolStatus] = field(default_factory=list)

    def count_by_severity(self) -> Counter:
        return Counter(f.severity for f in self.findings)

    def count_by_category(self) -> Counter:
        return Counter(f.category for f in self.findings)

    def tool_notes(self) -> str:
        """Short text naming tools that did not (fully) run; empty if all ran."""
        parts = [f"{t.name} ({t.state.value})" for t in self.tool_statuses
                 if t.state is not ToolState.OK]
        return ("Tools not fully run: " + ", ".join(parts) + ".") if parts else ""


@dataclass
class ScanContext:
    """What project-level analyzers may need besides single files."""
    config: ScanConfig
    root: Path
    files: List[DiscoveredFile]
    is_single_file: bool
    cancel: threading.Event
    emit: Emit
    # display names of files the parser rejected; external tools skip them
    syntax_error_files: Set[str] = field(default_factory=set)


class ScanTargetError(Exception):
    """The chosen target cannot be scanned at all."""


def scan_issue(file: str, rule_id: str, message: str,
               severity: Severity = Severity.WARNING) -> Finding:
    return Finding("Scanner", rule_id, severity, Category.SCAN,
                   Confidence.DEFINITE, file, None, message)


# --------------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------------

class FileDiscovery:
    def __init__(self, config: ScanConfig, cancel: threading.Event,
                 on_progress: Optional[Callable[[int], None]] = None):
        self.config = config
        self.cancel = cancel
        self.on_progress = on_progress

    def run(self) -> DiscoveryResult:
        target = self.config.target
        try:
            mode = target.stat().st_mode
        except OSError as exc:
            raise ScanTargetError(
                f"Cannot access '{target}': {exc.strerror or exc}") from exc

        if stat.S_ISDIR(mode):
            return self._scan_folder(target)
        if stat.S_ISREG(mode):
            if target.suffix.lower() != ".py":
                raise ScanTargetError(f"'{target.name}' is not a .py file.")
            result = DiscoveryResult()
            self._add_file(target, target.parent, result)
            return result
        raise ScanTargetError(f"'{target}' is not a regular file or folder.")

    def _scan_folder(self, root: Path) -> DiscoveryResult:
        result = DiscoveryResult()

        def on_error(exc: OSError) -> None:
            name = _display_path(Path(exc.filename or root), root)
            result.errors.append((name, f"Folder could not be read: {exc.strerror or exc}"))

        for dirpath, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
            if self.cancel.is_set():
                result.cancelled = True
                break
            if self.config.recursive:
                dirnames[:] = sorted(d for d in dirnames if not self._is_ignored(dirpath, d))
            else:
                dirnames[:] = []
            for name in sorted(filenames):
                if name.lower().endswith(".py"):
                    self._add_file(Path(dirpath) / name, root, result)
            if self.on_progress and len(result.files) >= DISCOVERY_PROGRESS_STEP:
                self.on_progress(len(result.files))

        result.files.sort(key=lambda f: f.display.lower())
        return result

    def _is_ignored(self, dirpath: str, name: str) -> bool:
        if any(fnmatch.fnmatch(name, pattern) for pattern in self.config.ignored_dirs):
            return True
        return os.path.isfile(os.path.join(dirpath, name, "pyvenv.cfg"))

    def _add_file(self, path: Path, root: Path, result: DiscoveryResult) -> None:
        display = _display_path(path, root)
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.errors.append((display, f"File could not be accessed: {exc.strerror or exc}"))
            return
        if size > self.config.max_file_size:
            limit_mb = self.config.max_file_size / (1024 * 1024)
            result.skipped.append((display, f"larger than the {limit_mb:g} MB limit ({format_size(size)})"))
            return
        result.files.append(DiscoveredFile(path, display, size))


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def discovery_issues(discovery: DiscoveryResult) -> List[Finding]:
    issues = [scan_issue(name, "file-skipped", f"File skipped: {reason}", Severity.INFO)
              for name, reason in discovery.skipped]
    issues += [scan_issue(name, "path-unreadable", message)
               for name, message in discovery.errors]
    return issues


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


# --------------------------------------------------------------------------
# Secret detection primitives and masking
#
# One set of detectors serves two purposes:
#   * detection (strict filters, produces findings)
#   * redaction (loose filters, used to scrub every snippet/message that
#     comes from ANY analyzer before it is stored in a Finding)
# --------------------------------------------------------------------------

PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "passphrase"})
SENSITIVE_WORDS = PASSWORD_WORDS | {"secret", "token", "credential", "credentials", "apikey"}
SENSITIVE_PAIRS = frozenset({
    ("api", "key"), ("access", "key"), ("private", "key"),
    ("auth", "key"), ("signing", "key"), ("encryption", "key"),
})
# A name ending in one of these describes the secret, it is not the secret.
SAFE_LAST_WORDS = frozenset({
    "url", "uri", "path", "file", "dir", "name", "type", "field", "header", "env",
    "prefix", "suffix", "endpoint", "format", "length", "ttl", "expiry", "expires",
    "timeout", "label", "help", "regex", "pattern", "id", "hash", "count", "size",
    "mode", "algorithm", "alg", "param", "params", "keyword", "var", "variable",
    "location", "text", "message", "msg", "placeholder", "description", "desc",
    "error", "errors", "prompt", "title", "hint", "required", "enabled", "flag",
    "policy", "scheme", "kind", "style", "class", "source", "provider", "manager",
})

_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")


def _split_name(name: str) -> List[str]:
    name = _CAMEL_RE.sub(r"\1_\2", name)
    return [p for p in re.split(r"[^A-Za-z0-9]+", name.lower()) if p]


def is_sensitive_name(name: str) -> bool:
    parts = _split_name(name)
    if not parts or parts[-1] in SAFE_LAST_WORDS:
        return False
    if any(p in SENSITIVE_WORDS for p in parts):
        return True
    return any(pair in SENSITIVE_PAIRS for pair in zip(parts, parts[1:]))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in Counter(text).values())


def _char_classes(text: str) -> int:
    return sum((
        any(c.islower() for c in text),
        any(c.isupper() for c in text),
        any(c.isdigit() for c in text),
        any(not c.isalnum() for c in text),
    ))


_PLACEHOLDER_RE = re.compile(
    r"""^(?:<.*>|\$\{.*\}|\$[A-Za-z_]\w*|\{\{.*\}\}|%\(.*\)s|%s|\{[a-z_]*\}
        |x{3,}|\*{3,}|\.{3,}|-+|_+|\d{1,2}
        |none|null|nil|todo|tbd|pass|password|passwd|secret|token|test|testing
        |change[-_ ]?me.*|replace[-_ ]?me.*|your[-_ ].*|my[-_ ]?(?:password|secret|token|key).*
        |example.*|sample.*|dummy.*|fake.*|placeholder.*|insert.*|enter.*|redacted|hidden|masked
        |foo|bar|baz|env|environment)$""",
    re.IGNORECASE | re.VERBOSE,
)


def is_placeholder(value: str) -> bool:
    v = value.strip()
    low = v.lower()
    if "example" in low or "placeholder" in low:
        return True
    if len(set(v)) <= 2:
        return True
    return bool(_PLACEHOLDER_RE.match(v))


def mask_value(value: str) -> str:
    """Hide a sensitive value; keeps at most a short prefix of long values."""
    n = len(value)
    reveal = 0 if n < 12 else min(4, n // 6)
    return f"{value[:reveal]}****({n} chars)"


_STRING_LITERAL_RE = re.compile(r"""(?P<q>["'])(?:\\.|(?!(?P=q)).)*(?P=q)""")


def mask_string_literals(text: str) -> str:
    return _STRING_LITERAL_RE.sub(lambda m: m.group("q") + "****" + m.group("q"), text)


@dataclass(frozen=True)
class SecretCandidate:
    start: int
    end: int
    rule_id: str
    label: str
    severity: Severity
    confidence: Confidence
    value: str = field(repr=False, compare=False)  # raw value: transient, never stored in findings


_KNOWN_TOKEN_PATTERNS: Tuple[Tuple[str, str, "re.Pattern[str]"], ...] = (
    ("secret-aws-access-key", "AWS access key ID",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret-github-token", "GitHub token",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})")),
    ("secret-slack-token", "Slack token",
     re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("secret-google-api-key", "Google API key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("secret-stripe-key", "Stripe live secret key",
     re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}")),
    ("secret-anthropic-key", "Anthropic API key",
     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("secret-openai-key", "OpenAI-style API key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("secret-jwt", "JSON Web Token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)
_URL_CRED_RE = re.compile(
    r"""\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@'"<>]+:(?P<value>[^\s@'"<>/]{3,})@""")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_PEM_BODY_RE = re.compile(r"^\s*[A-Za-z0-9+/]{40,}={0,2}\s*$")
_ASSIGN_RE = re.compile(
    r"""(?<![A-Za-z0-9_])(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*
        (?::\s*[A-Za-z_][\w\[\], .|]*?)?\s*=(?!=)\s*[rRuUbB]{0,2}
        (?P<q>["'])(?P<value>(?:\\.|(?!(?P=q)).)*)(?P=q)""",
    re.VERBOSE)
_DICT_RE = re.compile(
    r"""["'](?P<name>[A-Za-z_][A-Za-z0-9_\-. ]*)["']\s*:\s*[rRuUbB]{0,2}
        (?P<q>["'])(?P<value>(?:\\.|(?!(?P=q)).)*)(?P=q)""",
    re.VERBOSE)
_ENTROPY_RE = re.compile(r"""["'](?P<value>[A-Za-z0-9+/=_\-]{32,})["']""")
_HEX_DIGEST_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|"
                            r"[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_URL_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")
_LOWER_IDENT_RE = re.compile(r"^[a-z]+(?:[_.\-][a-z]+)*$")
_UPPER_IDENT_RE = re.compile(r"^[A-Z]+(?:[_.\-][A-Z]+)*$")
_IGNORE_MARKERS = ("secret-scan: ignore", "pragma: allowlist secret")


def _assigned_rule(name: str) -> Tuple[str, str]:
    parts = _split_name(name)
    if any(p in PASSWORD_WORDS for p in parts):
        return "secret-password", "Possible hardcoded password"
    if "token" in parts:
        return "secret-token", "Possible hardcoded token"
    return "secret-api-key", "Possible hardcoded secret or API key"


def _classify_assigned_value(name: str, value: str) -> Optional[Tuple[Severity, Confidence]]:
    """Strict filter for 'sensitive_name = "literal"'. None means: not a secret."""
    v = value.strip()
    parts = _split_name(name)
    min_len = 6 if any(p in PASSWORD_WORDS for p in parts) else 8
    if not min_len <= len(v) <= 256:
        return None
    if is_placeholder(v) or v.count(" ") >= 2 or _URL_PREFIX_RE.match(v):
        return None
    if v.startswith(("/", "./", "../", "~/")) or _WINDOWS_PATH_RE.match(v):
        return None
    if _LOWER_IDENT_RE.match(v) or _UPPER_IDENT_RE.match(v):
        return None
    classes = _char_classes(v)
    entropy = shannon_entropy(v)
    has_digit_or_symbol = any(not c.isalpha() for c in v)
    if len(v) >= 16 and entropy >= 3.5 and classes >= 3:
        return Severity.WARNING, Confidence.HIGH
    if has_digit_or_symbol and entropy >= 2.5:
        return Severity.WARNING, Confidence.MEDIUM
    return Severity.INFO, Confidence.LOW


def _entropy_candidate_ok(value: str) -> bool:
    if _HEX_DIGEST_RE.match(value) or _UUID_RE.match(value):
        return False
    return _char_classes(value) >= 3 and shannon_entropy(value) >= 4.2


def find_secret_candidates(line: str, strict: bool = True) -> List[SecretCandidate]:
    """Find sensitive values in one line. strict=False is used for masking."""
    found: List[SecretCandidate] = []

    def add(cand: SecretCandidate) -> None:
        if any(cand.start < e and s < cand.end for s, e in
               ((c.start, c.end) for c in found)):
            return  # overlaps a stronger detection that was added earlier
        found.append(cand)

    for rule_id, label, rx in _KNOWN_TOKEN_PATTERNS:
        for m in rx.finditer(line):
            if strict and "example" in m.group(0).lower():
                continue
            add(SecretCandidate(m.start(), m.end(), rule_id, label,
                                Severity.ERROR, Confidence.HIGH, m.group(0)))

    for m in _URL_CRED_RE.finditer(line):
        value = m.group("value")
        if strict and (is_placeholder(value) or value[0] in "{$%<"):
            continue
        add(SecretCandidate(m.start("value"), m.end("value"), "secret-url-password",
                            "Password embedded in a URL", Severity.WARNING,
                            Confidence.HIGH, value))

    for rx in (_ASSIGN_RE, _DICT_RE):
        for m in rx.finditer(line):
            name, value = m.group("name"), m.group("value")
            if not value or not is_sensitive_name(name):
                continue
            rule_id, label = _assigned_rule(name)
            if strict:
                verdict = _classify_assigned_value(name, value)
                if verdict is None:
                    continue
                severity, confidence = verdict
            else:
                severity, confidence = Severity.WARNING, Confidence.MEDIUM
            add(SecretCandidate(m.start("value"), m.end("value"), rule_id, label,
                                severity, confidence, value))

    for m in _ENTROPY_RE.finditer(line):
        value = m.group("value")
        if _entropy_candidate_ok(value):
            add(SecretCandidate(m.start("value"), m.end("value"), "secret-high-entropy",
                                "High-entropy string that may be a secret",
                                Severity.INFO, Confidence.LOW, value))
    return found


def redact_text(text: str) -> str:
    """Mask anything that looks sensitive. Applied to every stored snippet/message."""
    if not text:
        return text
    out_lines = []
    for line in text.split("\n"):
        line = line[:MAX_SECRET_LINE_CHARS]
        if _PEM_BODY_RE.match(line):
            out_lines.append("****(key material redacted)")
            continue
        header = _PRIVATE_KEY_RE.search(line)
        if header:
            out_lines.append(line[:header.end()] + " [key material redacted]")
            continue
        for cand in sorted(find_secret_candidates(line, strict=False),
                           key=lambda c: c.start, reverse=True):
            line = line[:cand.start] + mask_value(cand.value) + line[cand.end:]
        out_lines.append(line)
    return "\n".join(out_lines)


def make_snippet(line: Optional[str]) -> Optional[str]:
    """Redacted, shortened source line for a finding."""
    if line is None:
        return None
    text = redact_text(line.strip())
    return text[:SNIPPET_MAX_CHARS] if text else None


# --------------------------------------------------------------------------
# Analyzers: base classes
# --------------------------------------------------------------------------

@dataclass
class SourceFile:
    path: Path
    display: str
    data: bytes
    _parsed: bool = field(default=False, repr=False)
    _tree: Optional[ast.AST] = field(default=None, repr=False)
    _error: Optional[Exception] = field(default=None, repr=False)

    def parse(self) -> ast.AST:
        """Parse once; analyzers share the result. Never executes the code."""
        if not self._parsed:
            self._parsed = True
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self._tree = ast.parse(self.data, filename=self.display)
            except Exception as exc:  # SyntaxError, ValueError, RecursionError, MemoryError
                self._error = exc
        if self._error is not None:
            raise self._error
        assert self._tree is not None
        return self._tree

    def line_text(self, lineno: Optional[int]) -> Optional[str]:
        if not lineno or lineno < 1:
            return None
        text = self.data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        return lines[lineno - 1] if lineno <= len(lines) else None


class Analyzer:
    """Analyzer life cycle per scan: prepare() -> analyze(file)* -> finalize()."""

    name = ""
    builtin = True

    def prepare(self, ctx: ScanContext) -> List[Finding]:
        return []

    def analyze(self, source: SourceFile) -> List[Finding]:
        return []

    def finalize(self, ctx: ScanContext) -> List[Finding]:
        return []

    def tool_status(self) -> ToolStatus:
        return ToolStatus(self.name, True, ToolState.OK, detail="built-in")


class SyntaxAnalyzer(Analyzer):
    """Parses each file with the interpreter's own grammar; nothing is executed."""

    name = "Syntax (ast)"

    def analyze(self, source: SourceFile) -> List[Finding]:
        try:
            source.parse()
        except SyntaxError as exc:
            return [self._syntax_finding(source, exc)]
        except ValueError as exc:
            return [Finding(self.name, "unparsable-file", Severity.ERROR, Category.SYNTAX,
                            Confidence.DEFINITE, source.display, None,
                            f"File cannot be parsed: {exc}")]
        except (RecursionError, MemoryError):
            return [scan_issue(source.display, "parse-limit",
                               "File is too deeply nested or too large to parse; syntax was not checked.")]
        return []

    def _syntax_finding(self, source: SourceFile, exc: SyntaxError) -> Finding:
        snippet = make_snippet(exc.text) if exc.text else None
        return Finding(self.name, type(exc).__name__, Severity.ERROR, Category.SYNTAX,
                       Confidence.DEFINITE, source.display, exc.lineno,
                       exc.msg or "Invalid syntax", snippet)


# --------------------------------------------------------------------------
# Secret scanner
# --------------------------------------------------------------------------

class SecretScanner(Analyzer):
    """Regex + entropy detection of credentials. Raw values never leave this class:
    findings carry a masked value and a redacted snippet only."""

    name = "Secrets"

    def analyze(self, source: SourceFile) -> List[Finding]:
        data = source.data
        if b"\x00" in data[:8192]:
            return []  # binary data, not text
        findings: List[Finding] = []
        text = data.decode("utf-8", errors="replace")
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line[:MAX_SECRET_LINE_CHARS]
            lowered = line.lower()
            if any(marker in lowered for marker in _IGNORE_MARKERS):
                continue
            header = _PRIVATE_KEY_RE.search(line)
            if header:
                findings.append(Finding(
                    self.name, "secret-private-key", Severity.ERROR, Category.SECRET,
                    Confidence.HIGH, source.display, lineno,
                    "Private key block found in source (key material not shown).",
                    (line[:header.end()] + " [key material redacted]")[:SNIPPET_MAX_CHARS]))
            for cand in find_secret_candidates(line, strict=True):
                findings.append(Finding(
                    self.name, cand.rule_id, cand.severity, Category.SECRET,
                    cand.confidence, source.display, lineno,
                    f"{cand.label} (value masked: {mask_value(cand.value)}).",
                    make_snippet(line)))
        return findings


# --------------------------------------------------------------------------
# Dependency analyzer (offline)
# --------------------------------------------------------------------------

def normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


# Import name -> distribution name(s) when they differ. Not exhaustive.
IMPORT_TO_DIST: Dict[str, Tuple[str, ...]] = {
    "PIL": ("pillow",), "cv2": ("opencv-python", "opencv-python-headless", "opencv-contrib-python"),
    "yaml": ("pyyaml",), "sklearn": ("scikit-learn",), "skimage": ("scikit-image",),
    "bs4": ("beautifulsoup4",), "dateutil": ("python-dateutil",), "dotenv": ("python-dotenv",),
    "jwt": ("pyjwt",), "serial": ("pyserial",), "Crypto": ("pycryptodome", "pycryptodomex"),
    "Cryptodome": ("pycryptodomex",), "OpenSSL": ("pyopenssl",), "attr": ("attrs",),
    "usb": ("pyusb",), "git": ("gitpython",), "docx": ("python-docx",), "pptx": ("python-pptx",),
    "magic": ("python-magic",), "MySQLdb": ("mysqlclient",),
    "psycopg2": ("psycopg2-binary", "psycopg2"), "zmq": ("pyzmq",), "wx": ("wxpython",),
    "gi": ("pygobject",), "Xlib": ("python-xlib",), "jose": ("python-jose",),
    "socks": ("pysocks",), "slugify": ("python-slugify",), "ldap": ("python-ldap",),
    "nacl": ("pynacl",), "discord": ("discord-py",), "telegram": ("python-telegram-bot",),
    "win32api": ("pywin32",), "win32con": ("pywin32",), "pythoncom": ("pywin32",),
    "pywintypes": ("pywin32",), "fitz": ("pymupdf",), "jnius": ("pyjnius",),
    "multipart": ("python-multipart",), "engineio": ("python-engineio",),
    "socketio": ("python-socketio",), "flask_cors": ("flask-cors",),
    "flask_sqlalchemy": ("flask-sqlalchemy",), "pkg_resources": ("setuptools",),
    "mpl_toolkits": ("matplotlib",), "Levenshtein": ("levenshtein", "python-levenshtein"),
    "googleapiclient": ("google-api-python-client",), "google.protobuf": ("protobuf",),
    "google.auth": ("google-auth",), "google.oauth2": ("google-auth",),
    "google.generativeai": ("google-generativeai",), "sqlalchemy": ("sqlalchemy",),
    "tensorflow": ("tensorflow", "tensorflow-cpu", "tensorflow-gpu"),
}

_OTHER_MANIFESTS = ("setup.py", "setup.cfg", "Pipfile", "environment.yml", "poetry.lock")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")


@lru_cache(maxsize=1)
def stdlib_module_names() -> FrozenSet[str]:
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return frozenset(names)
    result: Set[str] = set(sys.builtin_module_names)
    stdlib_dir = sysconfig.get_paths().get("stdlib")
    if stdlib_dir:
        for directory in (stdlib_dir, os.path.join(stdlib_dir, "lib-dynload")):
            try:
                entries = os.listdir(directory)
            except OSError:
                continue
            for entry in entries:
                if entry.endswith(".py"):
                    result.add(entry[:-3])
                elif "." in entry:
                    result.add(entry.split(".", 1)[0])
                elif os.path.isdir(os.path.join(directory, entry)):
                    result.add(entry)
    result.discard("site-packages")
    result.discard("dist-packages")
    return frozenset(result)


@lru_cache(maxsize=1)
def installed_import_map() -> Dict[str, Tuple[str, ...]]:
    """Import name -> distribution, from metadata of installed packages (Python 3.10+).

    Only unambiguous (one distribution) names are used; namespace packages such as
    'google' are skipped."""
    try:
        from importlib.metadata import packages_distributions  # type: ignore
        mapping = packages_distributions()
    except Exception:
        return {}
    return {top: tuple(dists) for top, dists in mapping.items() if len(dists) == 1}


def requirement_name(spec: str) -> Optional[str]:
    """Distribution name from a requirement line, or None if it has none."""
    spec = spec.strip()
    if not spec or spec.startswith(("#", "-")):
        return None
    egg = _EGG_RE.search(spec)
    if egg:
        return normalize_dist_name(egg.group(1))
    if "://" in spec.split("@", 1)[0] or spec.startswith((".", "/", "~")) \
            or spec.startswith(("git+", "hg+", "svn+", "bzr+", "file:")):
        return None
    m = _REQ_NAME_RE.match(spec)
    return normalize_dist_name(m.group(1)) if m else None


@dataclass
class DeclaredDependency:
    name: str       # normalized
    raw: str        # as written
    source: str     # manifest display name
    line: Optional[int]


@dataclass
class _ImportRecord:
    file: str
    line: int
    snippet: Optional[str]
    all_optional: bool
    other_files: Set[str] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)   # names taken via "from module import name"


def _read_manifest_text(path: Path) -> str:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(f"file is larger than {MAX_MANIFEST_BYTES // 1024} KB")
    return path.read_bytes().decode("utf-8-sig", errors="replace")


def _load_toml_module():
    try:
        import tomllib  # type: ignore
        return tomllib
    except ImportError:
        pass
    try:
        import tomli  # type: ignore
        return tomli
    except ImportError:
        return None


def _catches_import_error(handlers: Sequence[ast.ExceptHandler]) -> bool:
    for handler in handlers:
        if handler.type is None:
            return True
        nodes = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        for node in nodes:
            ident = node.id if isinstance(node, ast.Name) else getattr(node, "attr", "")
            if ident in ("ImportError", "ModuleNotFoundError", "Exception", "BaseException"):
                return True
    return False


def _is_type_checking(test: ast.expr) -> bool:
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def iter_imports(tree: ast.AST) -> Iterator[Tuple[str, int, bool, Tuple[str, ...]]]:
    """Yield (module, line, optional, imported_names) for absolute imports. Walks statements only,
    so deeply nested expressions cannot cause recursion problems."""
    try_types = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())
    stack: List[Tuple[Sequence[ast.stmt], bool]] = [(getattr(tree, "body", []), False)]
    while stack:
        stmts, optional = stack.pop()
        for node in stmts:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield alias.name, node.lineno, optional, ()
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    yield (node.module, node.lineno, optional,
                           tuple(a.name for a in node.names if a.name != "*"))
            elif isinstance(node, try_types):
                guarded = optional or _catches_import_error(node.handlers)
                stack.append((node.body, guarded))
                for handler in node.handlers:
                    stack.append((handler.body, optional))
                stack.append((node.orelse, optional))
                stack.append((node.finalbody, optional))
            elif isinstance(node, ast.If):
                typing_only = optional or _is_type_checking(node.test)
                stack.append((node.body, typing_only))
                stack.append((node.orelse, optional))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                   ast.For, ast.AsyncFor, ast.While,
                                   ast.With, ast.AsyncWith)):
                stack.append((node.body, optional))
                stack.append((getattr(node, "orelse", []), optional))
            elif hasattr(ast, "Match") and isinstance(node, ast.Match):
                for case in node.cases:
                    stack.append((case.body, optional))


class DependencyAnalyzer(Analyzer):
    """Compares imports with declared dependencies. Offline; results are hints
    ('possible'), never certain errors."""

    name = "Dependencies"

    def prepare(self, ctx: ScanContext) -> List[Finding]:
        self._root = ctx.root
        self._stdlib = stdlib_module_names()
        self._installed = installed_import_map()
        self._local_cache: Dict[str, FrozenSet[str]] = {}
        self._third_party: Dict[str, _ImportRecord] = {}
        self._own_names: Set[str] = set()
        return []

    # -- per file: collect third-party imports ------------------------------

    def _local_names(self, directory: Path) -> FrozenSet[str]:
        key = str(directory)
        cached = self._local_cache.get(key)
        if cached is not None:
            return cached
        names: Set[str] = set()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name.endswith(".py"):
                        names.add(entry.name[:-3])
                    else:
                        try:
                            if entry.is_dir(follow_symlinks=False) and entry.name.isidentifier():
                                names.add(entry.name)
                        except OSError:
                            continue
        except OSError:
            pass
        result = frozenset(names)
        self._local_cache[key] = result
        return result

    def analyze(self, source: SourceFile) -> List[Finding]:
        try:
            tree = source.parse()
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return []  # already reported by the syntax analyzer
        local: Optional[FrozenSet[str]] = None
        for module, lineno, optional, names in iter_imports(tree):
            top = module.split(".", 1)[0]
            if top in self._stdlib or top == "__main__":
                continue
            if local is None:
                local = (self._local_names(source.path.parent)
                         | self._local_names(self._root)
                         | self._local_names(self._root / "src"))
            if top in local:
                continue
            record = self._third_party.get(module)
            if record is None:
                record = self._third_party[module] = _ImportRecord(
                    source.display, lineno, make_snippet(source.line_text(lineno)), optional)
            else:
                record.all_optional = record.all_optional and optional
                if source.display != record.file:
                    record.other_files.add(source.display)
            record.names.update(names)
        return []

    # -- project level: compare with manifests ------------------------------

    def finalize(self, ctx: ScanContext) -> List[Finding]:
        declared, sources, issues = self._load_manifests(ctx.root)
        present_other = [n for n in _OTHER_MANIFESTS if (ctx.root / n).exists()]
        findings = list(issues)
        modules = sorted(self._third_party)

        if not sources:
            if modules:
                hint = f" Found but not analyzed: {', '.join(present_other)}." if present_other else ""
                shown = ", ".join(sorted({m.split('.', 1)[0] for m in modules})[:10])
                findings.append(Finding(
                    self.name, "dep-no-manifest", Severity.INFO, Category.DEPENDENCY,
                    Confidence.POSSIBLE, PROJECT_LABEL, None,
                    "No requirements.txt or pyproject.toml with dependency information was found, "
                    f"so third-party imports could not be compared (for example: {shown}).{hint}"))
            return findings

        source_names = ", ".join(sorted(sources))
        note = f" (Also present but not analyzed: {', '.join(present_other)}.)" if present_other else ""
        declared_names = set(declared)
        matched: Set[str] = set()
        for module in modules:
            if module.split(".", 1)[0].lower() in self._own_names:
                continue
            rec = self._third_party[module]
            candidates = self._candidate_dists(module)
            for imported in rec.names:  # "from google.cloud import storage"
                candidates |= self._candidate_dists(f"{module}.{imported}")
            hit = candidates & declared_names
            if hit:
                matched |= hit
                continue
            extra = f" It is also imported in {len(rec.other_files)} other file(s)." if rec.other_files else ""
            if rec.all_optional:
                severity, kind = Severity.INFO, "an optional or type-checking-only import"
            else:
                severity, kind = Severity.WARNING, "an import"
            findings.append(Finding(
                self.name, "dep-undeclared", severity, Category.DEPENDENCY,
                Confidence.POSSIBLE, rec.file, rec.line,
                f"'{module}' ({kind}) looks like a third-party package, but no matching entry "
                f"was found in {source_names}. The dependency list may be incomplete; this "
                f"is a possible issue, not a confirmed error.{extra}{note}",
                rec.snippet))

        if not ctx.is_single_file and ctx.config.recursive:
            for dep in sorted(declared.values(), key=lambda d: (d.source, d.line or 0, d.name)):
                if dep.name in matched:
                    continue
                findings.append(Finding(
                    self.name, "dep-unused", Severity.INFO, Category.DEPENDENCY,
                    Confidence.LOW, dep.source, dep.line,
                    f"'{dep.raw}' is declared but no import of it was found in the scanned "
                    "files. It may be a tool, a plugin, or an indirect dependency "
                    "(possible, not confirmed)."))
        return findings

    def _candidate_dists(self, module: str) -> Set[str]:
        parts = module.split(".")
        out: Set[str] = set()
        for k in range(1, min(3, len(parts)) + 1):
            out.add(normalize_dist_name("-".join(parts[:k])))
            for dist in IMPORT_TO_DIST.get(".".join(parts[:k]), ()):
                out.add(normalize_dist_name(dist))
        for dist in self._installed.get(parts[0], ()):
            out.add(normalize_dist_name(dist))
        return out

    def _load_manifests(self, root: Path) -> Tuple[Dict[str, DeclaredDependency], Set[str], List[Finding]]:
        declared: Dict[str, DeclaredDependency] = {}
        sources: Set[str] = set()
        issues: List[Finding] = []
        seen: Set[str] = set()

        try:
            req_files = sorted(
                p for p in root.iterdir()
                if p.is_file() and re.fullmatch(r"requirements([-_.][\w.\-]+)?\.txt", p.name, re.I))
        except OSError:
            req_files = []
        for path in req_files:
            self._read_requirements(path, root, declared, sources, issues, seen, depth=0)

        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            self._read_pyproject(pyproject, declared, sources, issues)
        return declared, sources, issues

    def _read_requirements(self, path: Path, root: Path, declared, sources, issues,
                           seen: Set[str], depth: int) -> None:
        display = _display_path(path, root)
        real = os.path.realpath(path)
        if real in seen or depth > 5:
            return
        seen.add(real)
        try:
            text = _read_manifest_text(path)
        except (OSError, ValueError) as exc:
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else exc
            issues.append(scan_issue(display, "manifest-unreadable",
                                     f"{display} could not be read: {reason}"))
            return
        sources.add(display)
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = re.sub(r"(^|\s)#.*$", "", raw).strip()
            if not line:
                continue
            include = re.match(r"^(?:-r|--requirement)[\s=]+(\S+)", line)
            if include:
                target = (path.parent / include.group(1))
                try:
                    inside = os.path.realpath(target).startswith(os.path.realpath(root) + os.sep)
                except OSError:
                    inside = False
                if inside and target.is_file():
                    self._read_requirements(target, root, declared, sources, issues, seen, depth + 1)
                continue
            name = requirement_name(line)
            if name and name not in declared:
                declared[name] = DeclaredDependency(name, raw=name, source=display, line=lineno)
                m = _REQ_NAME_RE.match(line)
                if m:
                    declared[name].raw = m.group(1)

    def _read_pyproject(self, path: Path, declared, sources, issues) -> None:
        display = path.name
        toml = _load_toml_module()
        if toml is None:
            issues.append(scan_issue(
                display, "toml-unsupported",
                "pyproject.toml was not analyzed: this Python has no TOML parser "
                "(needs Python 3.11+ or the 'tomli' package).", Severity.INFO))
            return
        try:
            data = toml.loads(_read_manifest_text(path))
        except (OSError, ValueError) as exc:  # TOMLDecodeError is a ValueError
            issues.append(scan_issue(display, "manifest-unreadable",
                                     f"pyproject.toml could not be parsed: {exc}"))
            return

        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
        poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
        groups = data.get("dependency-groups")
        has_info = bool(project or poetry or groups)
        if not has_info:
            return
        sources.add(display)

        for key in ("name",):
            for container in (project, poetry):
                value = container.get(key)
                if isinstance(value, str) and value:
                    self._own_names.add(value.lower().replace("-", "_"))

        def add(spec) -> None:
            if isinstance(spec, str):
                name = requirement_name(spec)
                if name and name not in declared:
                    m = _REQ_NAME_RE.match(spec)
                    declared[name] = DeclaredDependency(name, m.group(1) if m else name, display, None)

        for spec in project.get("dependencies", []) or []:
            add(spec)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for specs in optional.values():
                for spec in specs or []:
                    add(spec)
        if isinstance(groups, dict):
            for specs in groups.values():
                for spec in specs or []:
                    add(spec)  # dict entries (include-group) are skipped by add()
        uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
        for spec in uv.get("dev-dependencies", []) or []:
            add(spec)

        def add_poetry_table(table) -> None:
            if isinstance(table, dict):
                for key in table:
                    if key.lower() != "python":
                        add(key)

        add_poetry_table(poetry.get("dependencies"))
        add_poetry_table(poetry.get("dev-dependencies"))
        poetry_groups = poetry.get("group")
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if isinstance(group, dict):
                    add_poetry_table(group.get("dependencies"))



# --------------------------------------------------------------------------
# Built-in bug and security pattern checks
# --------------------------------------------------------------------------

def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


class _RiskVisitor(ast.NodeVisitor):
    """Conservative AST checks. These report suspicious patterns, not proof of bugs."""

    def __init__(self, source: SourceFile):
        self.source = source
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, int]] = set()
        self._async_depth = 0
        self._finally_depth = 0

    def add(self, rule: str, message: str, node: ast.AST,
            severity: Severity = Severity.WARNING,
            category: Category = Category.QUALITY,
            confidence: Confidence = Confidence.MEDIUM) -> None:
        line = getattr(node, "lineno", None)
        key = (rule, line or 0)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            "Built-in checks", rule, severity, category, confidence,
            self.source.display, line, message,
            make_snippet(self.source.line_text(line))))

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        leaf = name.rsplit(".", 1)[-1]
        if self._async_depth and name == "time.sleep":
            self.add("BUG-BLOCKING-SLEEP", "time.sleep blocks the event loop inside async code; use await asyncio.sleep instead.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
        if leaf in {"eval", "exec"} and name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.add("SEC-DYNAMIC-EXEC", "Dynamic code execution via eval/exec can run untrusted input.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                    "subprocess.check_call", "subprocess.check_output"}:
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and bool(k.value.value)
                   for k in node.keywords):
                self.add("SEC-SHELL-TRUE", "Subprocess uses shell=True; untrusted arguments can lead to command injection.",
                         node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            self.add("SEC-PICKLE", "Unpickling data from an untrusted source can execute arbitrary code.",
                     node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name == "yaml.load":
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            if loader is None or _dotted_name(loader) not in {"yaml.SafeLoader", "SafeLoader"}:
                self.add("SEC-YAML-LOAD", "yaml.load is used without a clearly safe loader; prefer yaml.safe_load.",
                         node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name.startswith("requests.") and any(
            k.arg == "verify" and isinstance(k.value, ast.Constant) and not bool(k.value.value)
            for k in node.keywords
        ):
            self.add("SEC-TLS-VERIFY-OFF", "TLS certificate verification is disabled for this request.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        broad = node.type is None or _dotted_name(node.type) in {"Exception", "BaseException"}
        if broad and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add("BUG-SILENT-EXCEPTION", "An exception is silently ignored; failures may disappear without a trace.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
        elif node.type is None:
            self.add("BUG-BARE-EXCEPT", "A bare except catches nearly every exception; catch specific exception types.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
        self.generic_visit(node)

    def _check_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        for value in defaults:
            if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                self.add("BUG-MUTABLE-DEFAULT", "A mutable list/dict/set is used as a default argument and is shared between calls.",
                         value, Severity.WARNING, Category.QUALITY, Confidence.HIGH)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_defaults(node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        comparators = [node.left] + list(node.comparators)
        for op, right in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Is, ast.IsNot)):
                values = (node.left, right)
                if any(isinstance(v, ast.Constant) and v.value not in (None, True, False)
                       for v in values):
                    self.add("BUG-IDENTITY-COMPARE", "Use == or != for value comparison; 'is' checks object identity.",
                             node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
                    break
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        seen = set()
        for key in node.keys:
            if key is None:
                continue
            try:
                value = ast.literal_eval(key)
                if value in seen:
                    self.add("BUG-DUPLICATE-DICT-KEY", "This dictionary contains a duplicate constant key; an earlier value will be overwritten.",
                             key, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
                seen.add(value)
            except (ValueError, TypeError, SyntaxError):
                continue
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self.add("QUALITY-STAR-IMPORT", "Wildcard import hides which names are used and can create name conflicts.",
                     node, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        self.generic_visit(node)


    def _check_function_metrics(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Report maintainability pressure without pretending it is a runtime bug."""
        positional = len(node.args.posonlyargs) + len(node.args.args)
        keyword_only = len(node.args.kwonlyargs)
        total_args = positional + keyword_only
        if node.args.vararg is not None:
            total_args += 1
        if node.args.kwarg is not None:
            total_args += 1
        if total_args > 8:
            self.add("QUALITY-TOO-MANY-ARGS",
                     f"Function '{node.name}' accepts {total_args} parameters; consider grouping related options.",
                     node, Severity.INFO, Category.QUALITY, Confidence.HIGH)

        first = getattr(node, "lineno", None)
        last = getattr(node, "end_lineno", first)
        if first and last:
            line_count = max(1, last - first + 1)
            if line_count > 100:
                self.add("QUALITY-LONG-FUNCTION",
                         f"Function '{node.name}' spans {line_count} lines; splitting it may make defects easier to isolate.",
                         node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
            elif line_count > 60:
                self.add("QUALITY-LARGE-FUNCTION",
                         f"Function '{node.name}' spans {line_count} lines; consider extracting focused helpers.",
                         node, Severity.INFO, Category.QUALITY, Confidence.HIGH)

        # Count decisions in this function only. Nested functions/classes are
        # intentionally excluded so their complexity is not charged twice.
        decisions = 1
        class LocalCounter(ast.NodeVisitor):
            def visit_FunctionDef(self, child):
                if child is node:
                    for statement in child.body:
                        self.visit(statement)
            def visit_AsyncFunctionDef(self, child):
                if child is node:
                    for statement in child.body:
                        self.visit(statement)
            def visit_ClassDef(self, child):
                return
            def visit_If(self, child):
                nonlocal decisions
                decisions += 1
                self.generic_visit(child)
            def visit_For(self, child):
                nonlocal decisions
                decisions += 1
                self.generic_visit(child)
            def visit_AsyncFor(self, child):
                nonlocal decisions
                decisions += 1
                self.generic_visit(child)
            def visit_While(self, child):
                nonlocal decisions
                decisions += 1
                self.generic_visit(child)
            def visit_IfExp(self, child):
                nonlocal decisions
                decisions += 1
                self.generic_visit(child)
            def visit_ExceptHandler(self, child):
                nonlocal decisions
                decisions += 1
                self.generic_visit(child)
            def visit_BoolOp(self, child):
                nonlocal decisions
                decisions += max(0, len(child.values) - 1)
                self.generic_visit(child)
            def visit_Lambda(self, child):
                return
        LocalCounter().visit(node)
        if decisions >= 18:
            self.add("QUALITY-VERY-COMPLEX-FUNCTION",
                     f"Function '{node.name}' has an estimated decision complexity of {decisions}; split branches or extract helpers.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.MEDIUM)
        elif decisions >= 12:
            self.add("QUALITY-COMPLEX-FUNCTION",
                     f"Function '{node.name}' has an estimated decision complexity of {decisions}; review its control flow.",
                     node, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._check_defaults(node)
        self._check_function_metrics(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._async_depth += 1
        try:
            self._visit_function(node)
        finally:
            self._async_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:  # noqa: C901 - rule dispatch is intentionally explicit
        name = _dotted_name(node.func)
        leaf = name.rsplit(".", 1)[-1]
        if self._async_depth and name == "time.sleep":
            self.add("BUG-BLOCKING-SLEEP", "time.sleep blocks the event loop inside async code; use await asyncio.sleep instead.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
        if leaf in {"eval", "exec"} and name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.add("SEC-DYNAMIC-EXEC", "Dynamic code execution via eval/exec can run untrusted input.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                    "subprocess.check_call", "subprocess.check_output"}:
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and bool(k.value.value)
                   for k in node.keywords):
                self.add("SEC-SHELL-TRUE", "Subprocess uses shell=True; untrusted arguments can lead to command injection.",
                         node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            self.add("SEC-PICKLE", "Unpickling data from an untrusted source can execute arbitrary code.",
                     node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name == "yaml.load":
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            if loader is None or _dotted_name(loader) not in {"yaml.SafeLoader", "SafeLoader"}:
                self.add("SEC-YAML-LOAD", "yaml.load is used without a clearly safe loader; prefer yaml.safe_load.",
                         node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name.startswith("requests.") and any(
            k.arg == "verify" and isinstance(k.value, ast.Constant) and not bool(k.value.value)
            for k in node.keywords
        ):
            self.add("SEC-TLS-VERIFY-OFF", "TLS certificate verification is disabled for this request.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name in {"os.system", "os.popen"}:
            self.add("SEC-OS-SHELL", f"{name} invokes a system shell; avoid constructing commands from untrusted data.",
                     node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name == "tempfile.mktemp":
            self.add("SEC-TEMPFILE-MKTEMP", "tempfile.mktemp is race-prone; use NamedTemporaryFile or mkstemp.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name in {"ssl._create_unverified_context", "_ssl._create_unverified_context"}:
            self.add("SEC-SSL-VERIFY-OFF", "An SSL context is created without certificate verification.",
                     node, Severity.ERROR, Category.SECURITY, Confidence.HIGH)
        if name in {"hashlib.md5", "hashlib.sha1"}:
            self.add("SEC-WEAK-HASH", f"{name} is not suitable for modern security-sensitive hashing.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant):
            if str(node.args[0].value).lower() in {"md5", "sha1"}:
                self.add("SEC-WEAK-HASH", "A weak hash algorithm is requested through hashlib.new.",
                         node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name in {"requests.get", "requests.post", "requests.put", "requests.delete",
                    "requests.patch", "requests.head", "requests.request"}:
            if not any(k.arg == "timeout" for k in node.keywords):
                self.add("QUALITY-HTTP-NO-TIMEOUT",
                         "HTTP request has no explicit timeout; a stalled connection may block the program indefinitely.",
                         node, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        if name == "urllib.request.urlopen" and not any(k.arg == "timeout" for k in node.keywords):
            self.add("QUALITY-URLLIB-NO-TIMEOUT",
                     "urlopen has no explicit timeout; network calls should normally be bounded.",
                     node, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        if name in {"yaml.unsafe_load", "yaml.load_all"}:
            self.add("SEC-YAML-UNSAFE", f"{name} may construct unsafe objects from untrusted YAML.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.HIGH)
        if name in {"tarfile.TarFile.extractall", "TarFile.extractall"}:
            self.add("SEC-TAR-EXTRACT", "Archive extraction should validate member paths and prevent path traversal.",
                     node, Severity.WARNING, Category.SECURITY, Confidence.MEDIUM)
        if name in {"subprocess.run", "subprocess.Popen", "subprocess.call",
                    "subprocess.check_call", "subprocess.check_output"}:
            if not any(k.arg == "shell" for k in node.keywords) and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    self.add("SEC-SUBPROCESS-STRING", "A subprocess command is supplied as one string; prefer an argument list when shell execution is not required.",
                             node, Severity.INFO, Category.SECURITY, Confidence.MEDIUM)
        # SQL APIs often accept a query plus values separately. Interpolating
        # values into the query string is risky; this is a warning, not proof.
        if leaf in {"execute", "executemany"} and node.args:
            query = node.args[0]
            interpolated = isinstance(query, (ast.JoinedStr, ast.BinOp))
            if isinstance(query, ast.Call) and _dotted_name(query.func).endswith(".format"):
                interpolated = True
            if interpolated:
                self.add("SEC-SQL-STRING-FORMAT", "SQL query appears to be built with string interpolation; use parameterized query placeholders.",
                         query, Severity.WARNING, Category.SECURITY, Confidence.MEDIUM)
        if name.endswith(".run") and any(k.arg == "debug" and isinstance(k.value, ast.Constant)
                                         and k.value.value is True for k in node.keywords):
            if name in {"app.run", "application.run"}:
                self.add("SEC-DEBUG-MODE", "A web application is started with debug=True; do not enable this in production.",
                         node, Severity.WARNING, Category.SECURITY, Confidence.MEDIUM)
        if leaf == "assert":
            self.add("QUALITY-ASSERT-CALL", "An assert-like callable is invoked; verify this is intentional.",
                     node, Severity.INFO, Category.QUALITY, Confidence.LOW)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        for statement in node.body:
            self.visit(statement)
        for handler in node.handlers:
            self.visit(handler)
        for statement in node.orelse:
            self.visit(statement)
        self._finally_depth += 1
        try:
            for statement in node.finalbody:
                self.visit(statement)
        finally:
            self._finally_depth -= 1

    def visit_TryStar(self, node: ast.AST) -> None:
        # Python 3.11 exception groups use the same final-body hazard.
        self.visit_Try(node)

    def visit_Return(self, node: ast.Return) -> None:
        if self._finally_depth:
            self.add("BUG-RETURN-IN-FINALLY",
                     "Returning from a finally block can suppress an exception or an earlier return value.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, right in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant) and right.value is None:
                self.add("QUALITY-NONE-COMPARE", "Use 'is None' or 'is not None' when checking against None.",
                         node, Severity.INFO, Category.QUALITY, Confidence.HIGH)
            if isinstance(op, (ast.Is, ast.IsNot)):
                values = (node.left, right)
                if any(isinstance(v, ast.Constant) and v.value not in (None, True, False)
                       for v in values):
                    self.add("BUG-IDENTITY-COMPARE", "Use == or != for value comparison; 'is' checks object identity.",
                             node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
                    break
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.add("QUALITY-ASSERT-STATEMENT", "Assertions can be removed when Python runs with optimization (-O); do not use them for required input validation.",
                 node, Severity.INFO, Category.QUALITY, Confidence.HIGH)
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        if isinstance(node.value, ast.Call) and _dotted_name(node.value.func) in {"time.sleep", "sleep"}:
            self.add("BUG-BLOCKING-SLEEP", "time.sleep blocks the event loop inside async code; consider asyncio.sleep.",
                     node, Severity.WARNING, Category.QUALITY, Confidence.HIGH)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.add("QUALITY-STAR-IMPORT", "Wildcard imports hide names and can create collisions.",
                         node, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self.add("QUALITY-STAR-IMPORT", "Wildcard import hides which names are used and can create name conflicts.",
                     node, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if isinstance(node.test, ast.Compare) and len(node.test.ops) == 1:
            op = node.test.ops[0]
            if isinstance(op, (ast.Eq, ast.NotEq)):
                left, right = node.test.left, node.test.comparators[0]
                if ((isinstance(left, ast.Constant) and left.value in (True, False)) or
                    (isinstance(right, ast.Constant) and right.value in (True, False))):
                    self.add("QUALITY-BOOL-COMPARE", "Comparing a value directly with True/False is usually clearer as a truthiness check.",
                             node.test, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            call_name = _dotted_name(item.context_expr.func) if isinstance(item.context_expr, ast.Call) else ""
            if call_name == "open":
                keywords = {k.arg for k in item.context_expr.keywords}
                # This only checks explicit text-mode encoding; binary mode is exempt.
                mode = next((a.value for a in item.context_expr.args[1:2]
                             if isinstance(a, ast.Constant)), "r")
                if "b" not in str(mode) and "encoding" not in keywords:
                    self.add("QUALITY-FILE-ENCODING", "Text file opened without an explicit encoding; behavior can vary by device or locale.",
                             item.context_expr, Severity.INFO, Category.QUALITY, Confidence.MEDIUM)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call) and _dotted_name(node.value.func) in {"print", "pprint.pprint"}:
            self.add("QUALITY-PRINT-DEBUG", "Debug output is written with print(); use logging or remove it from production paths when appropriate.",
                     node, Severity.INFO, Category.QUALITY, Confidence.LOW)
        self.generic_visit(node)


class BuiltinRiskAnalyzer(Analyzer):
    name = "Built-in bug & security checks"

    def analyze(self, source: SourceFile) -> List[Finding]:
        try:
            tree = source.parse()
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return []
        visitor = _RiskVisitor(source)
        visitor.visit(tree)
        return visitor.findings


# --------------------------------------------------------------------------
# External tools (Ruff, Bandit): safe subprocess execution
# --------------------------------------------------------------------------

@dataclass
class ToolRun:
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    cancelled: bool = False
    error: str = ""


class ToolOutputError(Exception):
    """A tool ran but its output could not be understood."""


def _tail(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    return redact_text(text[-limit:])


def run_tool(cmd: Sequence[str], cancel: threading.Event, timeout: float, cwd: str) -> ToolRun:
    """Run a command without a shell, with a timeout, cancellable, in a neutral
    working directory (never the scanned project: `python -m x` would otherwise
    import modules from the current directory)."""
    env = dict(os.environ)
    env["PYTHONSAFEPATH"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["NO_COLOR"] = "1"
    try:
        proc = subprocess.Popen(
            list(cmd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd, env=env, shell=False)
    except OSError as exc:
        return ToolRun(error=f"{exc.strerror or exc}")

    def kill() -> None:
        try:
            proc.kill()
            proc.communicate(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return

    deadline = time.monotonic() + timeout
    while True:
        try:
            out, err = proc.communicate(timeout=0.2)
            break
        except subprocess.TimeoutExpired:
            if cancel.is_set():
                kill()
                return ToolRun(cancelled=True)
            if time.monotonic() >= deadline:
                kill()
                return ToolRun(timed_out=True)
    return ToolRun(returncode=proc.returncode,
                   stdout=out.decode("utf-8", errors="replace"),
                   stderr=err.decode("utf-8", errors="replace"))


def _path_key(path: object) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


class ExternalToolAnalyzer(Analyzer):
    """Runs an optional command-line analyzer over the discovered files in chunks."""

    builtin = False
    executable = ""
    module = ""

    def __init__(self, command: Optional[Sequence[str]] = None):
        self._override = list(command) if command else None
        self._reset()

    def _reset(self) -> None:
        self._cmd: Optional[List[str]] = None
        self._state = ToolState.SKIPPED
        self._version = ""
        self._detail = "not run"
        self._ran = False

    # -- to be provided by subclasses
    def build_args(self, paths: Sequence[str]) -> List[str]:
        raise NotImplementedError

    def parse_output(self, run: ToolRun, mapping: Dict[str, DiscoveredFile]) -> List[Finding]:
        raise NotImplementedError

    # -- detection
    def _detect(self, cancel: threading.Event, workdir: str) -> Optional[Tuple[List[str], str]]:
        candidates: List[List[str]] = []
        if self._override:
            candidates.append(self._override)
        else:
            exe = shutil.which(self.executable)
            if exe:
                candidates.append([exe])
            if sys.executable:
                candidates.append([sys.executable, "-m", self.module])
        for cmd in candidates:
            run = run_tool(cmd + ["--version"], cancel, TOOL_VERSION_TIMEOUT, workdir)
            if run.returncode == 0 and run.stdout.strip():
                return cmd, run.stdout.strip().splitlines()[0][:80]
        return None

    def prepare(self, ctx: ScanContext) -> List[Finding]:
        self._reset()
        with tempfile.TemporaryDirectory(prefix="pyscanner_") as workdir:
            found = self._detect(ctx.cancel, workdir)
        if found is None:
            self._state = ToolState.MISSING
            self._detail = f"{self.name} is not installed or cannot be run here; its checks were skipped."
        else:
            self._cmd, self._version = found
            self._state = ToolState.OK
            self._detail = "ready"
        return []

    def finalize(self, ctx: ScanContext) -> List[Finding]:
        if self._state is not ToolState.OK or self._cmd is None:
            return []
        self._ran = True
        files = [f for f in ctx.files if f.display not in ctx.syntax_error_files]
        if not files:
            self._detail = "no parsable files to check"
            return []
        mapping = {_path_key(f.path): f for f in files}
        paths = [os.path.abspath(str(f.path)) for f in files]
        chunks = list(self._chunks(paths))
        findings: List[Finding] = []
        timeout = max(1, ctx.config.tool_timeout)
        with tempfile.TemporaryDirectory(prefix="pyscanner_") as workdir:
            for index, chunk in enumerate(chunks, 1):
                if ctx.cancel.is_set():
                    self._state, self._detail = ToolState.SKIPPED, "cancelled before completion"
                    return findings
                ctx.emit("status", f"Running {self.name} ({index}/{len(chunks)})...")
                run = run_tool(self._cmd + self.build_args(chunk), ctx.cancel, timeout, workdir)
                if run.cancelled:
                    self._state, self._detail = ToolState.SKIPPED, "cancelled before completion"
                    return findings
                if run.timed_out:
                    self._state = ToolState.TIMEOUT
                    self._detail = f"timed out after {timeout}s on batch {index}/{len(chunks)}; results are partial"
                    findings.append(scan_issue(PROJECT_LABEL, "tool-timeout",
                                               f"{self.name} {self._detail}."))
                    return findings
                if run.error:
                    self._state = ToolState.FAILED
                    self._detail = f"could not be started: {run.error}"
                    findings.append(scan_issue(PROJECT_LABEL, "tool-failed",
                                               f"{self.name} {self._detail}."))
                    return findings
                try:
                    findings.extend(self.parse_output(run, mapping))
                except ToolOutputError as exc:
                    self._state = ToolState.FAILED
                    self._detail = f"failed on batch {index}/{len(chunks)}: {exc}"
                    findings.append(scan_issue(PROJECT_LABEL, "tool-failed",
                                               f"{self.name} {self._detail}"))
                    return findings
        self._detail = f"checked {len(files)} file(s)"
        return findings

    @staticmethod
    def _chunks(paths: Sequence[str]) -> Iterator[List[str]]:
        chunk: List[str] = []
        chars = 0
        for p in paths:
            if chunk and (len(chunk) >= TOOL_CHUNK_FILES or chars + len(p) > TOOL_CHUNK_CHARS):
                yield chunk
                chunk, chars = [], 0
            chunk.append(p)
            chars += len(p) + 1
        if chunk:
            yield chunk

    def tool_status(self) -> ToolStatus:
        state, detail = self._state, self._detail
        if state is ToolState.OK and not self._ran:
            state, detail = ToolState.SKIPPED, "the scan ended before this tool ran"
        return ToolStatus(self.name, False, state, self._version, detail)

    # -- helpers for parsers
    @staticmethod
    def _load_json(text: str, name: str, run: ToolRun):
        text = text.strip()
        if not text:
            if run.returncode in (0, None):
                return None
            raise ToolOutputError(f"exit code {run.returncode}, no output. {_tail(run.stderr)}")
        start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=0)
        try:
            return json.loads(text[start:])
        except ValueError:
            raise ToolOutputError(
                f"output is not valid JSON (exit code {run.returncode}). {_tail(run.stderr)}") from None

    @staticmethod
    def _source_line(cache: Dict[str, List[str]], item: DiscoveredFile, line: Optional[int]) -> Optional[str]:
        if not line or line < 1:
            return None
        lines = cache.get(item.display)
        if lines is None:
            try:
                lines = item.path.read_bytes().decode("utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            cache[item.display] = lines
        return lines[line - 1] if line <= len(lines) else None


def _ruff_severity(code: str) -> Severity:
    if code.startswith(("E9", "F63", "F70", "F72", "F82")):
        return Severity.ERROR
    if code.startswith(("F", "W")):
        return Severity.WARNING
    return Severity.INFO


# Pyflakes (unused imports/variables, undefined names, ...), a few common
# correctness checks, and invalid escape sequences.
RUFF_SELECT = "F,E711,E712,E713,E714,E721,E722,E9,W605"


class RuffAnalyzer(ExternalToolAnalyzer):
    name = "Ruff"
    executable = "ruff"
    module = "ruff"

    def build_args(self, paths: Sequence[str]) -> List[str]:
        # Read-only: no --fix. --isolated ignores config files found in the project.
        return ["check", "--output-format", "json", "--no-cache", "--isolated",
                "--exit-zero", "--select", RUFF_SELECT, "--", *paths]

    def parse_output(self, run: ToolRun, mapping: Dict[str, DiscoveredFile]) -> List[Finding]:
        data = self._load_json(run.stdout, self.name, run)
        if data is None:
            return []
        if not isinstance(data, list):
            raise ToolOutputError("unexpected JSON structure")
        findings: List[Finding] = []
        cache: Dict[str, List[str]] = {}
        for entry in data:
            if not isinstance(entry, dict):
                continue
            item = mapping.get(_path_key(entry.get("filename", "")))
            if item is None:
                continue
            code = entry.get("code")
            message = redact_text(str(entry.get("message", "")))
            if not code:
                continue  # syntax errors are reported by the built-in syntax analyzer
            if code == "E902":
                findings.append(scan_issue(item.display, "ruff-unreadable",
                                           f"Ruff could not read this file: {message}", Severity.INFO))
                continue
            location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
            line = location.get("row") if isinstance(location.get("row"), int) else None
            findings.append(Finding(
                self.name, str(code), _ruff_severity(str(code)), Category.QUALITY,
                Confidence.HIGH, item.display, line, message,
                make_snippet(self._source_line(cache, item, line))))
        return findings


_BANDIT_SEVERITY = {"HIGH": Severity.ERROR, "MEDIUM": Severity.WARNING, "LOW": Severity.INFO}
_BANDIT_CONFIDENCE = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}
HARDCODED_PASSWORD_RULES = frozenset({"B105", "B106", "B107"})
_BANDIT_CODE_LINE_RE = re.compile(r"^(\d+)\s?(.*)$")


class BanditAnalyzer(ExternalToolAnalyzer):
    name = "Bandit"
    executable = "bandit"
    module = "bandit"

    def build_args(self, paths: Sequence[str]) -> List[str]:
        return ["-f", "json", "-q", "--exit-zero", *paths]

    @staticmethod
    def _code_line(code: str, line: Optional[int]) -> Optional[str]:
        first = None
        for raw in (code or "").splitlines():
            m = _BANDIT_CODE_LINE_RE.match(raw)
            if not m:
                continue
            if first is None:
                first = m.group(2)
            if line is not None and int(m.group(1)) == line:
                return m.group(2)
        return first

    def parse_output(self, run: ToolRun, mapping: Dict[str, DiscoveredFile]) -> List[Finding]:
        data = self._load_json(run.stdout, self.name, run)
        if data is None:
            return []
        if not isinstance(data, dict):
            raise ToolOutputError("unexpected JSON structure")
        findings: List[Finding] = []
        for err in data.get("errors", []) or []:
            if not isinstance(err, dict):
                continue
            reason = str(err.get("reason", "unknown error"))
            if "syntax" in reason.lower():
                continue  # reported by the built-in syntax analyzer
            item = mapping.get(_path_key(err.get("filename", "")))
            findings.append(scan_issue(item.display if item else PROJECT_LABEL, "bandit-file-error",
                                       f"Bandit could not analyze this file: {_tail(reason)}"))
        for res in data.get("results", []) or []:
            if not isinstance(res, dict):
                continue
            item = mapping.get(_path_key(res.get("filename", "")))
            if item is None:
                continue
            rule = str(res.get("test_id", "bandit"))
            line = res.get("line_number") if isinstance(res.get("line_number"), int) else None
            code_line = self._code_line(str(res.get("code", "")), line)
            if rule in HARDCODED_PASSWORD_RULES:
                # Bandit echoes the literal in message and code; never keep it.
                message = "Possible hardcoded password (value masked)."
                snippet = make_snippet(mask_string_literals(code_line)) if code_line else None
            else:
                message = redact_text(str(res.get("issue_text", "")))
                snippet = make_snippet(code_line)
            findings.append(Finding(
                self.name, rule,
                _BANDIT_SEVERITY.get(str(res.get("issue_severity", "")).upper(), Severity.WARNING),
                Category.SECURITY,
                _BANDIT_CONFIDENCE.get(str(res.get("issue_confidence", "")).upper(), Confidence.MEDIUM),
                item.display, line, message, snippet))
        return findings


# --------------------------------------------------------------------------
# Scan engine and background execution
# --------------------------------------------------------------------------

class FindingDeduper:
    """Drops duplicate findings, including the same hardcoded password reported
    by both the secret scanner and Bandit."""

    def __init__(self) -> None:
        self._seen: Set[Tuple] = set()
        self._secret_lines: Set[Tuple[str, Optional[int]]] = set()

    def accept(self, f: Finding) -> bool:
        key = (f.tool, f.rule_id, f.file, f.line, f.message)
        if key in self._seen:
            return False
        if f.category is Category.SECRET and f.line is not None:
            self._secret_lines.add((f.file, f.line))
        if (f.tool == "Bandit" and f.rule_id in HARDCODED_PASSWORD_RULES
                and (f.file, f.line) in self._secret_lines):
            return False
        self._seen.add(key)
        return True


def build_default_engine() -> "ScanEngine":
    return ScanEngine([SyntaxAnalyzer(), BuiltinRiskAnalyzer(), SecretScanner(), DependencyAnalyzer(),
                       RuffAnalyzer(), BanditAnalyzer()])


class ScanEngine:
    def __init__(self, analyzers: Sequence[Analyzer]):
        self.analyzers = list(analyzers)

    def run(self, config: ScanConfig, cancel: threading.Event, emit: Emit) -> ScanResult:
        clock_start = time.monotonic()
        result = ScanResult(
            target=config.target,
            analyzers=[a.name for a in self.analyzers],
            started_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        )
        dedupe = FindingDeduper()

        emit("status", "Searching for Python files...")
        discovery = FileDiscovery(
            config, cancel,
            on_progress=lambda n: emit("status", f"Searching... {n} files found"),
        ).run()
        files = discovery.files
        result.files_total = len(files)
        result.files_skipped = len(discovery.skipped)
        emit("files", files)
        self._record(result, dedupe, discovery_issues(discovery), emit)

        is_dir = config.target.is_dir()
        ctx = ScanContext(config=config, root=config.target if is_dir else config.target.parent,
                          files=files, is_single_file=not is_dir, cancel=cancel, emit=emit)

        disabled: Dict[int, str] = {}   # id(analyzer) -> reason it stopped working
        for analyzer in self.analyzers:
            self._record(result, dedupe,
                         self._guarded(analyzer, "prepare", PROJECT_LABEL,
                                       lambda a=analyzer: a.prepare(ctx), disabled), emit)

        for index, item in enumerate(files):
            if cancel.is_set():
                break
            emit("progress", (index, len(files), item.display))
            self._record(result, dedupe, self._scan_file(item, ctx, disabled), emit)
            result.files_scanned += 1
        emit("progress", (result.files_scanned, len(files), ""))

        cancelled = (discovery.cancelled or result.files_scanned < len(files)
                     or cancel.is_set())
        if not cancelled:
            for analyzer in self.analyzers:
                if cancel.is_set():
                    cancelled = True
                    break
                if id(analyzer) in disabled:
                    continue
                self._record(result, dedupe,
                             self._guarded(analyzer, "finalize", PROJECT_LABEL,
                                           lambda a=analyzer: a.finalize(ctx), disabled), emit)
            cancelled = cancelled or cancel.is_set()

        for analyzer in self.analyzers:
            result.tool_statuses.append(self._status_of(analyzer, disabled))

        result.findings.sort(key=lambda f: (f.file.lower(), f.line or 0, f.tool, f.rule_id))
        result.duration_seconds = time.monotonic() - clock_start
        result.status = self._final_status(result, cancelled)
        return result

    def _scan_file(self, item: DiscoveredFile, ctx: ScanContext,
                   disabled: Dict[int, str]) -> List[Finding]:
        try:
            data = item.path.read_bytes()
        except OSError as exc:
            return [scan_issue(item.display, "file-unreadable",
                               f"File could not be read: {exc.strerror or exc}")]
        source = SourceFile(item.path, item.display, data)

        findings: List[Finding] = []
        for analyzer in self.analyzers:
            if id(analyzer) in disabled:
                continue
            try:
                findings.extend(analyzer.analyze(source))
            except Exception as exc:  # one failing analyzer must not stop the scan
                findings.append(scan_issue(
                    item.display, "analyzer-failed",
                    f"{analyzer.name} failed on this file: {type(exc).__name__}: {redact_text(str(exc))}"))
        if any(f.category is Category.SYNTAX or f.rule_id == "parse-limit" for f in findings):
            ctx.syntax_error_files.add(item.display)
        return findings

    @staticmethod
    def _guarded(analyzer: Analyzer, stage: str, label: str,
                 call: Callable[[], List[Finding]], disabled: Dict[int, str]) -> List[Finding]:
        try:
            return call()
        except Exception as exc:
            reason = f"{type(exc).__name__}: {redact_text(str(exc))}"
            disabled[id(analyzer)] = f"{stage} failed: {reason}"
            return [scan_issue(label, "analyzer-failed",
                               f"{analyzer.name} stopped during {stage}: {reason}")]

    @staticmethod
    def _status_of(analyzer: Analyzer, disabled: Dict[int, str]) -> ToolStatus:
        if id(analyzer) in disabled:
            return ToolStatus(analyzer.name, analyzer.builtin, ToolState.FAILED,
                              detail=disabled[id(analyzer)])
        try:
            return analyzer.tool_status()
        except Exception as exc:
            return ToolStatus(analyzer.name, analyzer.builtin, ToolState.FAILED,
                              detail=f"status unavailable: {type(exc).__name__}")

    @staticmethod
    def _record(result: ScanResult, dedupe: FindingDeduper,
                findings: List[Finding], emit: Emit) -> None:
        fresh = []
        for f in findings:
            if dedupe.accept(f):
                fresh.append(f)
            else:
                result.duplicates_removed += 1
        if fresh:
            result.findings.extend(fresh)
            emit("findings", fresh)

    @staticmethod
    def _final_status(result: ScanResult, cancelled: bool) -> ScanStatus:
        if cancelled:
            return ScanStatus.CANCELLED
        if any(f.category is Category.SCAN for f in result.findings):
            return ScanStatus.COMPLETED_WITH_ISSUES
        return ScanStatus.COMPLETED


def run_discovery(config: ScanConfig, cancel: threading.Event, emit: Emit) -> DiscoveryResult:
    result = FileDiscovery(
        config, cancel,
        on_progress=lambda n: emit("status", f"Searching... {n} files found"),
    ).run()
    emit("files", result.files)
    return result


class BackgroundTask(threading.Thread):
    """Runs a job off the UI thread and reports back through a queue."""

    def __init__(self, job: Callable[[threading.Event, Emit], object],
                 events: "queue.Queue[Tuple[str, object]]"):
        super().__init__(daemon=True)
        self._job = job
        self._events = events
        self.cancel_event = threading.Event()

    def _emit(self, kind: str, payload: object) -> None:
        self._events.put((kind, payload))

    def run(self) -> None:
        try:
            outcome = self._job(self.cancel_event, self._emit)
        except ScanTargetError as exc:
            self._emit("failed", str(exc))
        except Exception:
            self._emit("failed", "Unexpected internal error:\n" + traceback.format_exc())
        else:
            self._emit("finished", outcome)




def result_to_dict(result: ScanResult) -> Dict[str, object]:
    """Convert a scan result to a JSON-safe report; sensitive snippets stay redacted."""
    return {
        "application": APP_TITLE,
        "version": APP_VERSION,
        "target": str(result.target),
        "started_at": result.started_at,
        "status": result.status.value,
        "duration_seconds": round(result.duration_seconds, 3),
        "files_total": result.files_total,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "duplicates_removed": result.duplicates_removed,
        "tool_statuses": [
            {"name": t.name, "builtin": t.builtin, "state": t.state.value,
             "version": t.version, "detail": redact_text(t.detail)}
            for t in result.tool_statuses
        ],
        "findings": [
            {"tool": f.tool, "rule_id": f.rule_id, "severity": f.severity.value,
             "category": f.category.value, "confidence": f.confidence.value,
             "file": f.file, "line": f.line, "message": redact_text(f.message),
             "snippet": redact_text(f.snippet or "")}
            for f in result.findings
        ],
    }


def write_json_report(result: ScanResult, destination: Path) -> Path:
    destination = Path(destination)
    destination.write_text(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2),
                           encoding="utf-8")
    return destination



def _write_startup_log(message: str) -> None:
    """Write diagnostics in a location writable on Android and desktop."""
    try:
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        destinations = [Path("/storage/emulated/0/Download"), Path.home(), Path.cwd()]
        for folder in destinations:
            try:
                if folder.is_dir() and os.access(str(folder), os.W_OK):
                    with (folder / "python_scanner.log").open("a", encoding="utf-8") as stream:
                        stream.write(f"[{stamp}] {message.rstrip()}\n\n")
                    return
            except OSError:
                continue
    except Exception:
        pass


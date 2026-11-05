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

# ============================================================================
# Mobile interface (Kivy)
# ============================================================================

# Import Kivy defensively. A broken UI build should show an in-app diagnostic
# page whenever the Kivy window can be created, rather than leaving a blank view.
KIVY_AVAILABLE = False
KIVY_IMPORT_ERROR = ""
try:
    from kivy.app import App
    from kivy.clock import Clock
    from kivy.core.window import Window
    from kivy.graphics import Color, RoundedRectangle, Line, Ellipse, Rectangle
    from kivy.metrics import dp, sp
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.button import Button
    from kivy.uix.checkbox import CheckBox
    from kivy.uix.filechooser import FileChooserListView
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.label import Label
    from kivy.uix.popup import Popup
    from kivy.uix.progressbar import ProgressBar
    from kivy.uix.screenmanager import Screen, ScreenManager, FadeTransition
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.spinner import Spinner
    from kivy.uix.textinput import TextInput
    from kivy.uix.widget import Widget
    KIVY_AVAILABLE = True
except Exception as _kivy_error:
    KIVY_IMPORT_ERROR = f"{type(_kivy_error).__name__}: {_kivy_error}"
    _write_startup_log("KIVY_IMPORT_FAILED\n" + traceback.format_exc())


# Palette: deep ink background with turquoise/cyan neon accents.
C_BG = (0.018, 0.035, 0.055, 1)
C_SURFACE = (0.035, 0.075, 0.095, 1)
C_SURFACE_2 = (0.050, 0.105, 0.130, 1)
C_SURFACE_3 = (0.065, 0.135, 0.160, 1)
C_BORDER = (0.10, 0.32, 0.34, 1)
C_TEXT = (0.91, 0.98, 0.98, 1)
C_MUTED = (0.48, 0.66, 0.68, 1)
C_ACCENT = (0.12, 0.94, 0.84, 1)
C_ACCENT_SOFT = (0.10, 0.55, 0.52, 1)
C_BLUE = (0.30, 0.67, 1.0, 1)
C_RED = (1.0, 0.31, 0.40, 1)
C_ORANGE = (1.0, 0.68, 0.25, 1)
C_GREEN = (0.24, 0.90, 0.62, 1)


if KIVY_AVAILABLE:
    class NeonProgress(Widget):
        """Small custom progress indicator; avoids version-specific ProgressBar properties."""
        def __init__(self, **kwargs):
            self.max = 1.0
            self.value = 0.0
            super().__init__(**kwargs)
            with self.canvas:
                Color(*C_SURFACE_3)
                self._track = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(5)])
                Color(*C_ACCENT)
                self._fill = RoundedRectangle(pos=self.pos, size=(0, self.height), radius=[dp(5)])
            self.bind(pos=self._update_bar, size=self._update_bar)
            self._update_bar()

        def _update_bar(self, *_):
            maximum = max(1.0, float(self.max))
            ratio = max(0.0, min(1.0, float(self.value) / maximum))
            self._track.pos = self.pos
            self._track.size = self.size
            self._fill.pos = self.pos
            self._fill.size = (self.width * ratio, self.height)


    class NeonSurface(BoxLayout):
        """Reusable rounded panel with a subtle turquoise rim."""
        def __init__(self, fill=C_SURFACE, radius=dp(18), **kwargs):
            super().__init__(**kwargs)
            self._fill = fill
            self._radius = radius
            with self.canvas.before:
                self._bg_color = Color(*fill)
                self._bg = RoundedRectangle(pos=self.pos, size=self.size,
                                            radius=[radius])
                self._border_color = Color(*C_BORDER)
                self._border = Line(rounded_rectangle=(self.x, self.y,
                                                       self.width, self.height, radius),
                                    width=0.85)
            self.bind(pos=self._sync_canvas, size=self._sync_canvas)

        def _sync_canvas(self, *_):
            self._bg.pos = self.pos
            self._bg.size = self.size
            self._border.rounded_rectangle = (self.x, self.y, self.width,
                                              self.height, self._radius)


    class NeonButton(Button):
        def __init__(self, fill=C_ACCENT, text_color=C_BG, outline=False, **kwargs):
            self.fill = fill
            self.text_color = text_color
            self.outline = outline
            kwargs.setdefault("background_normal", "")
            kwargs.setdefault("background_down", "")
            kwargs.setdefault("background_color", (0, 0, 0, 0))
            kwargs.setdefault("color", text_color)
            kwargs.setdefault("bold", True)
            kwargs.setdefault("font_size", sp(14))
            kwargs.setdefault("size_hint_y", None)
            kwargs.setdefault("height", dp(50))
            super().__init__(**kwargs)
            with self.canvas.before:
                self._btn_color = Color(*(C_SURFACE_2 if outline else fill))
                self._btn_rect = RoundedRectangle(pos=self.pos, size=self.size,
                                                   radius=[dp(14)])
                self._line_color = Color(*(C_ACCENT if outline else fill))
                self._btn_line = Line(rounded_rectangle=(self.x, self.y,
                                                          self.width, self.height,
                                                          dp(14)), width=0.9 if outline else 0)
            self.bind(pos=self._sync_canvas, size=self._sync_canvas,
                      state=self._sync_state, disabled=self._sync_state)
            self._sync_state()

        def _sync_canvas(self, *_):
            self._btn_rect.pos = self.pos
            self._btn_rect.size = self.size
            self._btn_line.rounded_rectangle = (self.x, self.y, self.width,
                                                self.height, dp(14))

        def _sync_state(self, *_):
            if self.disabled:
                self._btn_color.rgba = (0.08, 0.12, 0.14, 1)
                self.color = C_MUTED
            elif self.state == "down":
                self._btn_color.rgba = tuple(v * 0.78 for v in self.fill[:3]) + (1,)
                self.color = self.text_color
            else:
                self._btn_color.rgba = C_SURFACE_2 if self.outline else self.fill
                self.color = C_TEXT if self.outline else self.text_color


    class NeonLabel(Label):
        def __init__(self, text="", color=C_TEXT, size=13, height=30,
                     halign="left", valign="middle", **kwargs):
            kwargs.setdefault("size_hint_y", None)
            kwargs.setdefault("height", dp(height))
            kwargs.setdefault("font_size", sp(size))
            kwargs.setdefault("color", color)
            kwargs.setdefault("halign", halign)
            kwargs.setdefault("valign", valign)
            super().__init__(text=text, **kwargs)
            self.bind(size=self._sync_text)
            self._sync_text()

        def _sync_text(self, *_):
            self.text_size = (max(1, self.width), None)


    class NeonMetric(NeonSurface):
        def __init__(self, caption, value="—", accent=C_ACCENT, **kwargs):
            super().__init__(orientation="vertical", padding=dp(12), spacing=dp(2),
                             size_hint_y=None, height=dp(98), **kwargs)
            self.add_widget(NeonLabel(text=value, size=24, color=accent,
                                      height=dp(42), bold=True, halign="center"))
            self.value_label = self.children[0]
            self.add_widget(NeonLabel(text=caption, size=10, color=C_MUTED,
                                      height=dp(24), bold=True, halign="center"))


    class PythonScannerApp(App):
        title = APP_TITLE

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.engine = build_default_engine()
            self.events = queue.Queue()
            self.task = None
            self.target = None
            self.last_result = None
            self.findings = []
            self.active_filter = "All"
            self.search_query = ""
            self.busy = False
            self.visible_limit = 120
            self._finding_popup = None
            self._toast_popup = None
            self._scan_config = None
            self._picker_request_code = 7412
            self._picker_mode = None
            self._android_picker_bound = False
            self._picker_activity = None
            self._last_picker_error = ""

        # ----- Startup / shell -----------------------------------------
        def build(self):
            try:
                Window.clearcolor = C_BG
                try:
                    Window.softinput_mode = "below_target"
                except Exception:
                    pass
                self.screen_manager = ScreenManager(transition=FadeTransition(duration=0.12))
                for screen_name, factory in (
                    ("home", self._build_home),
                    ("scan", self._build_scan),
                    ("results", self._build_results),
                    ("settings", self._build_settings),
                ):
                    screen = Screen(name=screen_name)
                    screen.add_widget(factory())
                    self.screen_manager.add_widget(screen)
                self.bottom_nav = self._build_bottom_nav()
                root = BoxLayout(orientation="vertical", spacing=0)
                root.add_widget(self.screen_manager)
                root.add_widget(self.bottom_nav)
                Clock.schedule_interval(self._poll_events, 0.10)
                return root
            except Exception:
                detail = traceback.format_exc()
                _write_startup_log("UI_BUILD_FAILED\n" + detail)
                return self._emergency_view(detail)

        def _emergency_view(self, detail):
            root = BoxLayout(orientation="vertical", padding=dp(22), spacing=dp(14))
            with root.canvas.before:
                Color(*C_BG)
                root._fallback_bg = Rectangle(pos=root.pos, size=root.size)
            root.bind(pos=lambda w, *_: setattr(w._fallback_bg, "pos", w.pos),
                      size=lambda w, *_: setattr(w._fallback_bg, "size", w.size))
            root.add_widget(NeonLabel(text="PYTHON SCANNER", size=22, color=C_ACCENT,
                                      bold=True, height=dp(48)))
            root.add_widget(NeonLabel(text="The main interface could not be built. This diagnostic screen is available instead.",
                                      size=15, color=C_TEXT, height=dp(60)))
            root.add_widget(NeonLabel(text="Error details were saved to python_scanner.log.",
                                      size=12, color=C_MUTED, height=dp(45)))
            error_box = ScrollView(do_scroll_x=False)
            error_label = Label(text=detail[-5000:], color=C_MUTED, font_size=sp(10),
                                halign="left", valign="top", size_hint_y=None)
            error_label.bind(width=lambda w, width: setattr(w, "text_size", (width, None)),
                             texture_size=lambda w, size: setattr(w, "height", size[1]))
            error_box.add_widget(error_label)
            root.add_widget(error_box)
            return root

        def _page(self, heading, subtitle):
            page = BoxLayout(orientation="vertical", padding=(dp(16), dp(12), dp(16), dp(8)),
                             spacing=dp(10))
            top = BoxLayout(size_hint_y=None, height=dp(66), spacing=dp(10))
            logo = NeonSurface(size_hint=(None, None), size=(dp(52), dp(52)),
                               padding=dp(2), radius=dp(16), fill=C_SURFACE_3)
            logo.add_widget(NeonLabel(text="</>", size=19, color=C_ACCENT,
                                      bold=True, halign="center"))
            top.add_widget(logo)
            titles = BoxLayout(orientation="vertical", spacing=0)
            titles.add_widget(NeonLabel(text=heading, size=20, height=dp(34), bold=True))
            titles.add_widget(NeonLabel(text=subtitle, size=10, height=dp(23), color=C_MUTED))
            top.add_widget(titles)
            page.add_widget(top)
            return page

        def _scroll(self, spacing=dp(11)):
            scroll = ScrollView(do_scroll_x=False, bar_width=dp(3),
                                scroll_type=["bars", "content"])
            body = BoxLayout(orientation="vertical", size_hint_y=None, spacing=spacing,
                             padding=(0, 0, 0, dp(12)))
            body.bind(minimum_height=body.setter("height"))
            scroll.add_widget(body)
            return scroll, body

        def _card(self, heading=None, hint=None, height=None, fill=C_SURFACE):
            card = NeonSurface(orientation="vertical", padding=dp(14), spacing=dp(8),
                               size_hint_y=None, height=height if height is not None else dp(80),
                               fill=fill)
            if height is None:
                card.bind(minimum_height=card.setter("height"))
            if heading:
                card.add_widget(NeonLabel(text=heading, size=14, color=C_TEXT,
                                          bold=True, height=dp(28)))
            if hint:
                card.add_widget(NeonLabel(text=hint, size=10, color=C_MUTED,
                                          height=dp(26)))
            return card

        def _button(self, text, callback, secondary=False, height=48):
            button = NeonButton(text=text,
                                fill=C_SURFACE_2 if secondary else C_ACCENT,
                                text_color=C_TEXT if secondary else C_BG,
                                outline=secondary, height=dp(height))
            button.bind(on_release=lambda *_: callback())
            return button

        def _build_bottom_nav(self):
            nav = NeonSurface(orientation="horizontal", padding=(dp(7), dp(5)),
                              spacing=dp(2), size_hint_y=None, height=dp(62),
                              radius=dp(14), fill=C_SURFACE)
            for title, page in (("Home", "home"), ("Scan", "scan"),
                                ("Results", "results"), ("Settings", "settings")):
                button = Button(text=title, background_normal="",
                                background_color=(0, 0, 0, 0),
                                color=C_ACCENT if self.screen_manager.current == page else C_MUTED,
                                font_size=sp(11), bold=True)
                button.bind(on_release=lambda _b, dest=page: self.go(dest))
                nav.add_widget(button)
            return nav

        def go(self, page):
            self.screen_manager.current = page
            self._refresh_nav()

        def _refresh_nav(self):
            if not hasattr(self, "bottom_nav"):
                return
            self.bottom_nav.clear_widgets()
            for title, page in (("Home", "home"), ("Scan", "scan"),
                                ("Results", "results"), ("Settings", "settings")):
                button = Button(text=title, background_normal="",
                                background_color=(0, 0, 0, 0),
                                color=C_ACCENT if self.screen_manager.current == page else C_MUTED,
                                font_size=sp(11), bold=True)
                button.bind(on_release=lambda _b, dest=page: self.go(dest))
                self.bottom_nav.add_widget(button)

        # ----- Home ----------------------------------------------------
        def _build_home(self):
            page = self._page("Python Scanner", "Professional Python static analysis")
            scroll, body = self._scroll()
            hero = NeonSurface(orientation="vertical", padding=dp(18), spacing=dp(10),
                               size_hint_y=None, height=dp(220), fill=C_SURFACE_2)
            hero.add_widget(NeonLabel(text="Inspect your code with confidence.", size=22,
                                      bold=True, color=C_TEXT, height=dp(42)))
            hero.add_widget(NeonLabel(
                text="Detect syntax errors, suspicious patterns, security risks, exposed secrets, and dependency issues without executing your code.",
                size=11, color=C_MUTED, height=dp(62)))
            hero.add_widget(self._button("＋   START NEW SCAN", lambda: self.go("scan")))
            body.add_widget(hero)

            stats = GridLayout(cols=2, spacing=dp(9), size_hint_y=None, height=dp(100))
            self.home_files = NeonMetric("Files Scanned", "—")
            self.home_findings = NeonMetric("Findings", "—", accent=C_BLUE)
            stats.add_widget(self.home_files)
            stats.add_widget(self.home_findings)
            body.add_widget(stats)

            recent = self._card("Latest Scan", height=dp(142))
            self.home_latest = NeonLabel(text="No scans have been run yet.", size=11,
                                         color=C_MUTED, height=dp(48))
            recent.add_widget(self.home_latest)
            recent.add_widget(self._button("VIEW RESULTS", lambda: self.go("results"),
                                           secondary=True, height=42))
            body.add_widget(recent)

            capabilities = self._card("WHAT WE CHECK", height=dp(208))
            for line in (
                "✓  Python syntax and AST structure",
                "✓  Common bugs and function complexity",
                "✓  Risky code patterns and security settings",
                "✓  Potential secrets with values masked",
                "✓  Dependencies and optional Ruff / Bandit tools",
            ):
                capabilities.add_widget(NeonLabel(text=line, size=10, color=C_MUTED,
                                                  height=dp(25)))
            body.add_widget(capabilities)
            page.add_widget(scroll)
            return page

        # ----- Scan page -----------------------------------------------
        def _build_scan(self):
            page = self._page("New Scan", "Choose a Python file or project folder")
            scroll, body = self._scroll()
            target_card = self._card("1. SELECT TARGET", "Choose a file from device storage or scan a project folder")
            self.target_label = NeonLabel(text="No target selected", size=11,
                                          color=C_MUTED, height=dp(52))
            target_card.add_widget(self.target_label)
            picker_row = GridLayout(cols=2, spacing=dp(8), size_hint_y=None,
                                    height=dp(52))
            picker_row.add_widget(self._button("CHOOSE .PY FILE", self.choose_file,
                                               secondary=True))
            picker_row.add_widget(self._button("CHOOSE FOLDER", self.choose_folder,
                                               secondary=True))
            target_card.add_widget(picker_row)
            body.add_widget(target_card)

            options = self._card("2. SCAN OPTIONS")
            recursive_row = BoxLayout(size_hint_y=None, height=dp(42), spacing=dp(8))
            recursive_row.add_widget(NeonLabel(text="Include subfolders", size=12,
                                               color=C_TEXT, height=dp(40)))
            self.recursive_check = CheckBox(active=True, size_hint=(None, None),
                                            size=(dp(46), dp(42)))
            recursive_row.add_widget(self.recursive_check)
            options.add_widget(recursive_row)
            options.add_widget(NeonLabel(text="Maximum file size (MB)", size=10,
                                         color=C_MUTED, height=dp(24)))
            self.max_size_input = TextInput(text=str(DEFAULT_MAX_FILE_MB), multiline=False,
                                            input_filter="float", size_hint_y=None,
                                            height=dp(44), padding=(dp(12), dp(10)),
                                            background_normal="", background_active="",
                                            background_color=C_SURFACE_2,
                                            foreground_color=C_TEXT, cursor_color=C_ACCENT,
                                            hint_text_color=C_MUTED, font_size=sp(14))
            options.add_widget(self.max_size_input)
            options.add_widget(NeonLabel(text="Ignored folders", size=10,
                                         color=C_MUTED, height=dp(24)))
            self.ignored_input = TextInput(
                text=", ".join(DEFAULT_IGNORED_DIRS[:12]), multiline=False,
                size_hint_y=None, height=dp(44), padding=(dp(12), dp(10)),
                background_normal="", background_active="",
                background_color=C_SURFACE_2, foreground_color=C_TEXT,
                cursor_color=C_ACCENT, font_size=sp(11))
            options.add_widget(self.ignored_input)
            body.add_widget(options)

            status = self._card("3. SCAN STATUS")
            self.scan_status = NeonLabel(text="Ready to scan", size=11,
                                         color=C_MUTED, height=dp(42))
            status.add_widget(self.scan_status)
            self.progress = NeonProgress(size_hint_y=None, height=dp(9))
            status.add_widget(self.progress)
            controls = GridLayout(cols=2, spacing=dp(8), size_hint_y=None,
                                  height=dp(50))
            self.scan_button = self._button("START SCAN", self.start_scan)
            self.cancel_button = self._button("CANCEL SCAN", self.cancel_scan,
                                               secondary=True)
            self.cancel_button.disabled = True
            controls.add_widget(self.scan_button)
            controls.add_widget(self.cancel_button)
            status.add_widget(controls)
            status.add_widget(NeonLabel(
                text="Safety: selected source files are read and analyzed, never executed.",
                size=9, color=C_MUTED, height=dp(42)))
            body.add_widget(status)
            page.add_widget(scroll)
            return page

        # ----- Results page --------------------------------------------
        def _build_results(self):
            page = self._page("Scan Report", "Tap any finding to inspect details")
            scroll, body = self._scroll(spacing=dp(9))
            summary = self._card("SCAN SUMMARY")
            self.results_summary = NeonLabel(text="No report available yet.", size=10,
                                             color=C_MUTED, height=dp(52))
            summary.add_widget(self.results_summary)
            metrics = GridLayout(cols=3, spacing=dp(6), size_hint_y=None, height=dp(102))
            self.result_errors = NeonMetric("Error", "—", accent=C_RED)
            self.result_warnings = NeonMetric("Warning", "—", accent=C_ORANGE)
            self.result_info = NeonMetric("Info", "—", accent=C_BLUE)
            for metric in (self.result_errors, self.result_warnings, self.result_info):
                metrics.add_widget(metric)
            summary.add_widget(metrics)
            body.add_widget(summary)

            controls = self._card("FILTER FINDINGS")
            self.filter_spinner = Spinner(text="All", values=("All", "Error", "Warning", "Info"),
                                          size_hint_y=None, height=dp(44),
                                          background_normal="", background_color=C_SURFACE_2,
                                          color=C_TEXT, font_size=sp(12))
            self.filter_spinner.bind(text=self._on_filter)
            controls.add_widget(self.filter_spinner)
            self.search_input = TextInput(hint_text="Search message, file, or rule ID...",
                                          multiline=False, size_hint_y=None, height=dp(44),
                                          padding=(dp(12), dp(10)), background_normal="",
                                          background_active="", background_color=C_SURFACE_2,
                                          foreground_color=C_TEXT, hint_text_color=C_MUTED,
                                          cursor_color=C_ACCENT, font_size=sp(11))
            self.search_input.bind(text=self._on_search)
            controls.add_widget(self.search_input)
            self.findings_count = NeonLabel(text="0 findings", color=C_ACCENT, size=10,
                                            height=dp(25), bold=True)
            controls.add_widget(self.findings_count)
            body.add_widget(controls)

            self.findings_list = BoxLayout(orientation="vertical", size_hint_y=None,
                                           spacing=dp(8))
            self.findings_list.bind(minimum_height=self.findings_list.setter("height"))
            body.add_widget(self.findings_list)
            self.load_more_button = self._button("LOAD MORE", self._load_more,
                                                  secondary=True)
            self.load_more_button.disabled = True
            body.add_widget(self.load_more_button)
            tools = self._card("TOOL STATUS")
            self.tool_status_label = NeonLabel(text="Tool status will appear here after a scan.",
                                               size=10, color=C_MUTED, height=dp(66))
            tools.add_widget(self.tool_status_label)
            body.add_widget(tools)
            footer = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(48))
            self.export_button = self._button("EXPORT JSON REPORT", self.export_report,
                                              secondary=True)
            self.export_button.disabled = True
            footer.add_widget(self.export_button)
            footer.add_widget(self._button("SCAN AGAIN", lambda: self.go("scan")))
            body.add_widget(footer)
            page.add_widget(scroll)
            return page

        def _build_settings(self):
            page = self._page("Settings", "Engine information, privacy, and limitations")
            scroll, body = self._scroll()
            about = self._card("ABOUT")
            about.add_widget(NeonLabel(text=f"Version {APP_VERSION}  •  Mobile Edition",
                                       size=11, color=C_ACCENT, height=dp(28)))
            about.add_widget(NeonLabel(
                text="Python Scanner performs static analysis. It never runs or imports selected project files; it only reads their source and structure.",
                size=11, color=C_MUTED, height=dp(68)))
            body.add_widget(about)
            engines = self._card("ANALYSIS ENGINES")
            for label in (
                "AST and syntax checks: Python built-in parser",
                "Bug and security checks: built-in AST rules",
                "Secrets: pattern and entropy checks with value masking",
                "Dependencies: imports compared with project manifests",
                "Ruff and Bandit: optional tools, enabled when installed",
            ):
                engines.add_widget(NeonLabel(text="•  " + label, size=10,
                                             color=C_MUTED, height=dp(30)))
            body.add_widget(engines)
            privacy = self._card("PRIVACY")
            privacy.add_widget(NeonLabel(
                text="Project contents are not uploaded. Reports are created only when you export them. Detected secret values are masked in reports.",
                size=11, color=C_MUTED, height=dp(78)))
            body.add_widget(privacy)
            limitations = self._card("STATIC ANALYSIS LIMITATIONS")
            limitations.add_widget(NeonLabel(
                text="Static analysis cannot prove every data-dependent, external-service, or runtime issue. Potential findings include a confidence level. Install Ruff and Bandit in a supported environment for additional checks.",
                size=11, color=C_MUTED, height=dp(100)))
            body.add_widget(limitations)
            page.add_widget(scroll)
            return page

        # ----- File and folder picker ----------------------------------
        def _picker_start(self):
            candidates = []
            if self.target:
                candidates.append(self.target if self.target.is_dir() else self.target.parent)
            candidates.extend((Path("/storage/emulated/0"), Path.home(), Path.cwd()))
            for candidate in candidates:
                try:
                    if candidate.exists() and candidate.is_dir() and os.access(str(candidate), os.R_OK):
                        return str(candidate)
                except OSError:
                    continue
            return str(Path.home())

        def _android_open_picker(self, folder=False):
            """Legacy SAF path retained for reference; not used by _show_picker."""
            try:
                self._picker_mode = "folder" if folder else "file"
                # Pydroid callbacks can originate outside Android's UI thread.
                # Clock.schedule_once guarantees the Java activity call is made
                # from Kivy's main thread instead of the worker thread.
                Clock.schedule_once(
                    lambda _dt: self._launch_android_picker_on_ui(folder), 0
                )
                return True
            except Exception:
                detail = traceback.format_exc()
                self._last_picker_error = detail.splitlines()[-1] if detail.splitlines() else "Unknown Android picker error"
                _write_startup_log("ANDROID_SAF_SCHEDULE_FAILED\n" + detail)
                return False

        def _launch_android_picker_on_ui(self, folder=False):
            """Launch Android's document picker from Pydroid's main activity."""
            try:
                # Pydroid uses the Ren'Py activity bootstrap. Set the Java
                # thread context loader to that activity's loader before
                # registering python-for-android's Java listener proxy.
                from android import activity as android_activity
                from jnius import autoclass, cast

                PythonActivity = autoclass("org.renpy.android.PythonActivity")
                raw_activity = PythonActivity.mActivity
                if raw_activity is None:
                    raise RuntimeError("Pydroid did not expose its current Android activity")

                Thread = autoclass("java.lang.Thread")
                java_thread = Thread.currentThread()
                previous_loader = java_thread.getContextClassLoader()
                activity_loader = raw_activity.getClass().getClassLoader()
                java_thread.setContextClassLoader(activity_loader)

                try:
                    if not self._android_picker_bound:
                        android_activity.bind(
                            on_activity_result=self._on_android_activity_result
                        )
                        self._android_picker_bound = True
                finally:
                    # Keep the app's Java thread context unchanged after
                    # proxy creation; Pyjnius retains the listener reference.
                    java_thread.setContextClassLoader(previous_loader)

                activity_instance = cast("android.app.Activity", raw_activity)
                self._picker_activity = activity_instance
                Intent = autoclass("android.content.Intent")

                if folder:
                    intent = Intent("android.intent.action.OPEN_DOCUMENT_TREE")
                    flags = (Intent.FLAG_GRANT_READ_URI_PERMISSION |
                             Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                             Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
                else:
                    intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
                    intent.addCategory(Intent.CATEGORY_OPENABLE)
                    intent.setType("*/*")
                    flags = (Intent.FLAG_GRANT_READ_URI_PERMISSION |
                             Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)

                intent.addFlags(flags)
                self._picker_mode = "folder" if folder else "file"
                activity_instance.startActivityForResult(
                    intent, int(self._picker_request_code)
                )
            except Exception as exc:
                detail = traceback.format_exc()
                # JavaException text contains the useful exception class and
                # message; the final traceback line often contains only
                # Thread.run(), which is not the actual cause.
                message = str(exc).strip() or type(exc).__name__
                self._last_picker_error = message[:240]
                _write_startup_log(
                    "ANDROID_PICKER_LAUNCH_FAILED\nEXCEPTION: " + message +
                    "\nTRACEBACK:\n" + detail
                )
                self._picker_mode = None
                self._toast("Picker failed: " + self._last_picker_error[:120])

        def _on_android_activity_result(self, request_code, result_code, intent):
            if request_code != self._picker_request_code:
                return
            mode = self._picker_mode
            self._picker_mode = None
            if result_code != -1 or intent is None:
                return
            try:
                from jnius import autoclass
                activity = getattr(self, "_picker_activity", None)
                if activity is None:
                    raise RuntimeError("The Android activity reference was lost before selection returned")
                DocumentsContract = autoclass("android.provider.DocumentsContract")
                OpenableColumns = autoclass("android.provider.OpenableColumns")
                resolver = activity.getContentResolver()
                uri = intent.getData()
                if uri is None:
                    raise RuntimeError("Android returned an empty document URI")
                try:
                    activity.getContentResolver().takePersistableUriPermission(
                        uri, intent.getFlags() & 3)
                except Exception:
                    pass

                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                import_root = Path(self.user_data_dir) / "scanner_imports" / stamp
                import_root.mkdir(parents=True, exist_ok=True)
                if mode == "file":
                    name = self._android_display_name(resolver, uri, OpenableColumns)
                    if not name.lower().endswith(".py"):
                        self._toast("Select a Python .py file.")
                        return
                    destination = import_root / Path(name).name
                    self._copy_android_uri(resolver, uri, destination)
                    self.set_target(destination)
                elif mode == "folder":
                    copied = self._copy_android_tree(resolver, DocumentsContract, uri, import_root)
                    if copied < 1:
                        self._toast("No readable Python files were found in this folder.")
                        return
                    self.set_target(import_root)
                    self._toast(f"Folder imported: {copied} files ready to scan.")
            except Exception as exc:
                detail = traceback.format_exc()
                message = str(exc).strip() or type(exc).__name__
                _write_startup_log(
                    "ANDROID_DOCUMENT_IMPORT_FAILED\nEXCEPTION: " + message +
                    "\nTRACEBACK:\n" + detail
                )
                self._toast("Import failed: " + message[:120])

        @staticmethod
        def _android_display_name(resolver, uri, OpenableColumns):
            cursor = resolver.query(uri, [OpenableColumns.DISPLAY_NAME], None, None, None)
            if cursor is not None:
                try:
                    if cursor.moveToFirst():
                        return str(cursor.getString(0) or "selected_file.py")
                finally:
                    cursor.close()
            return "selected_file.py"

        @staticmethod
        def _copy_android_uri(resolver, uri, destination):
            """Copy a SAF document through its file descriptor, not a guessed path."""
            descriptor = resolver.openFileDescriptor(uri, "r")
            if descriptor is None:
                raise OSError("Android could not open the selected document")
            fd = os.dup(descriptor.getFd())
            descriptor.close()
            with os.fdopen(fd, "rb") as source, open(destination, "wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)

        def _copy_android_tree(self, resolver, DocumentsContract, tree_uri, destination):
            """Import a selected folder from SAF into app storage for normal Path-based scanning."""
            from jnius import autoclass
            Document = autoclass("android.provider.DocumentsContract$Document")
            root_id = DocumentsContract.getTreeDocumentId(tree_uri)
            count = [0]
            total_bytes = [0]
            max_files = 10000
            max_total = 512 * 1024 * 1024

            def walk(parent_id, local_dir, depth=0):
                if depth > 40 or count[0] >= max_files:
                    return
                children_uri = DocumentsContract.buildChildDocumentsUriUsingTree(tree_uri, parent_id)
                columns = [Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME,
                           Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE]
                cursor = resolver.query(children_uri, columns, None, None, None)
                if cursor is None:
                    return
                try:
                    while cursor.moveToNext() and count[0] < max_files:
                        doc_id = str(cursor.getString(0))
                        name = str(cursor.getString(1) or "item")
                        mime = str(cursor.getString(2) or "")
                        safe_name = Path(name).name or "item"
                        if safe_name in (".", ".."):
                            continue
                        if mime == Document.MIME_TYPE_DIR:
                            child_dir = local_dir / safe_name
                            child_dir.mkdir(parents=True, exist_ok=True)
                            walk(doc_id, child_dir, depth + 1)
                        elif safe_name.lower().endswith(".py") or safe_name.lower() in (
                                "requirements.txt", "pyproject.toml"):
                            size = cursor.getLong(3) if not cursor.isNull(3) else 0
                            if size > MAX_FILE_MB_LIMIT * 1024 * 1024:
                                continue
                            if total_bytes[0] + max(0, size) > max_total:
                                return
                            document_uri = DocumentsContract.buildDocumentUriUsingTree(tree_uri, doc_id)
                            target = local_dir / safe_name
                            self._copy_android_uri(resolver, document_uri, target)
                            actual = target.stat().st_size
                            total_bytes[0] += actual
                            count[0] += 1
                finally:
                    cursor.close()

            walk(root_id, destination)
            return count[0]

        def _request_android_storage_access(self):
            """Ask Pydroid for Android's broad file access without SAF callbacks.

            Pydroid's android.activity result bridge can fail on its alternate
            PythonActivity class loader. This route deliberately avoids that
            bridge: Android opens the permission settings as a normal Activity,
            and Kivy's own file browser reads storage after the user returns.
            """
            try:
                from jnius import autoclass, cast
                BuildVersion = autoclass("android.os.Build$VERSION")
                if int(BuildVersion.SDK_INT) < 30:
                    return True
                Environment = autoclass("android.os.Environment")
                if bool(Environment.isExternalStorageManager()):
                    return True
                PythonActivity = None
                activity = None
                for class_name in ("org.renpy.android.PythonActivity",
                                   "org.kivy.android.PythonActivity"):
                    try:
                        PythonActivity = autoclass(class_name)
                        raw = PythonActivity.mActivity
                        if raw is not None:
                            activity = cast("android.app.Activity", raw)
                            break
                    except Exception:
                        continue
                if activity is None:
                    raise RuntimeError("Pydroid Android activity is unavailable")
                Intent = autoclass("android.content.Intent")
                Uri = autoclass("android.net.Uri")
                Settings = autoclass("android.provider.Settings")
                intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.setData(Uri.parse("package:" + str(activity.getPackageName())))
                try:
                    activity.startActivity(intent)
                except Exception:
                    # Some Android builds expose only the general access page.
                    fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    activity.startActivity(fallback)
                self._toast("Allow Pydroid to access all files. Return here and tap Select again.")
                return False
            except Exception:
                _write_startup_log("ANDROID_STORAGE_PERMISSION_FAILED\n" + traceback.format_exc())
                # Do not block the in-app browser if the device already grants
                # ordinary storage access or uses an older Android release.
                return True

        def _show_picker(self, folder=False):
            android_runtime = (sys.platform == "android" or
                               "ANDROID_ARGUMENT" in os.environ or
                               "ANDROID_ROOT" in os.environ or
                               os.path.isdir("/system/bin"))
            # On Android, always use the system DocumentsUI picker. The Kivy
            # FileChooserListView only sees app-accessible paths and often
            # appears empty on modern Android scoped-storage devices.
            if android_runtime:
                self._android_open_picker(folder=folder)
                return

            # Desktop fallback only.
            try:
                chooser = FileChooserListView(
                    path=self._picker_start(), dirselect=folder,
                    filters=[] if folder else ["*.py"], multiselect=False,
                    show_hidden=False)
                body = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(10))
                body.add_widget(chooser)
                popup = Popup(title="Choose Project Folder" if folder else "Choose Python File",
                              content=body, size_hint=(0.97, 0.92),
                              separator_color=C_ACCENT)
                actions = GridLayout(cols=2, spacing=dp(8), size_hint_y=None,
                                     height=dp(48))
                actions.add_widget(self._button("CANCEL", popup.dismiss,
                                                 secondary=True, height=46))

                def accept(*_):
                    selected = chooser.selection[0] if chooser.selection else (
                        chooser.path if folder else "")
                    if not selected:
                        self._toast("Choose a file or folder first.")
                        return
                    selected_path = Path(selected).expanduser()
                    if folder and not selected_path.is_dir():
                        self._toast("Please choose a folder for this option.")
                        return
                    if not folder and (not selected_path.is_file() or selected_path.suffix.lower() != ".py"):
                        self._toast("Only .py files are supported.")
                        return
                    popup.dismiss()
                    self.set_target(selected_path)

                actions.add_widget(self._button("SELECT THIS", accept, height=46))
                body.add_widget(actions)
                popup.open()
            except Exception:
                _write_startup_log("FILE_PICKER_FAILED\n" + traceback.format_exc())
                self._toast("The built-in file browser could not open.")

        def choose_file(self):
            self._show_picker(folder=False)

        def choose_folder(self):
            self._show_picker(folder=True)

        def set_target(self, target):
            path = Path(target).expanduser()
            if not path.exists() or not (path.is_file() or path.is_dir()):
                self._toast("The selected path is not readable.")
                return
            if path.is_file() and path.suffix.lower() != ".py":
                self._toast("Please select a .py file.")
                return
            self.target = path
            self.last_result = None
            self.findings = []
            self.visible_limit = 120
            self.export_button.disabled = True
            self._clear_results()
            kind = "Project folder" if path.is_dir() else "Python file"
            self.target_label.text = f"{kind}:  {path.name}\n{path.parent if path.is_file() else path}"
            self.target_label.color = C_TEXT
            self.scan_status.text = "Target selected. Ready to scan."
            self.scan_status.color = C_GREEN
            self.scan_button.disabled = self.busy
            self.go("scan")

        # ----- Scan lifecycle ------------------------------------------
        def _make_config(self):
            if not self.target:
                self._toast("Choose a file or folder first.")
                return None
            try:
                size_mb = float(self.max_size_input.text.strip())
                if not 0.05 <= size_mb <= MAX_FILE_MB_LIMIT:
                    raise ValueError
            except (ValueError, AttributeError):
                self._toast(f"File size must be between 0.05 and {MAX_FILE_MB_LIMIT} MB.")
                return None
            ignored = tuple(part.strip() for part in self.ignored_input.text.split(",")
                             if part.strip())
            return ScanConfig(target=self.target,
                              recursive=bool(self.recursive_check.active),
                              ignored_dirs=ignored or DEFAULT_IGNORED_DIRS,
                              max_file_size=int(size_mb * 1024 * 1024))

        def start_scan(self):
            if self.busy:
                return
            config = self._make_config()
            if config is None:
                return
            self._scan_config = config
            self.last_result = None
            self.findings = []
            self.visible_limit = 120
            self._clear_results()
            self.progress.max = 1
            self.progress.value = 0
            self.progress._update_bar()
            self.scan_status.text = "Preparing analysis engine..."
            self.scan_status.color = C_ACCENT
            self._set_busy(True)
            self.task = BackgroundTask(
                lambda cancel, emit: self.engine.run(config, cancel, emit), self.events)
            self.task.start()

        def cancel_scan(self):
            if self.task and self.task.is_alive() and not self.task.cancel_event.is_set():
                self.task.cancel_event.set()
                self.cancel_button.disabled = True
                self.scan_status.text = "Cancelling scan..."

        def _set_busy(self, busy):
            self.busy = busy
            if hasattr(self, "scan_button"):
                self.scan_button.disabled = busy or self.target is None
            if hasattr(self, "cancel_button"):
                self.cancel_button.disabled = not busy

        def _poll_events(self, _dt):
            for _ in range(MAX_EVENTS_PER_TICK):
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._dispatch(kind, payload)
                except Exception:
                    _write_startup_log("UI_EVENT_FAILED\n" + traceback.format_exc())
                    if hasattr(self, "scan_status"):
                        self.scan_status.text = "Could not display the result. See the error log."

        def _dispatch(self, kind, payload):
            if kind == "status":
                self.scan_status.text = str(payload)
            elif kind == "progress":
                done, total, current = payload
                self.progress.max = max(1, total)
                self.progress.value = done
                self.progress._update_bar()
                if current:
                    self.scan_status.text = f"Scanning {min(done + 1, total)} of {total}: {current}"
                else:
                    self.scan_status.text = f"Scanned {done} of {total} files"
            elif kind == "findings":
                # Keep the canonical list from the final result; this event is
                # only used for fast live feedback on the current scan.
                self.scan_status.text = f"{len(self.findings) + len(payload)} findings detected so far."
            elif kind == "finished":
                self._finish_scan(payload)
            elif kind == "failed":
                self._set_busy(False)
                self.scan_status.text = "Scan failed: " + str(payload)[:350]
                self.scan_status.color = C_RED
                _write_startup_log("SCAN_FAILED\n" + str(payload))
                self._toast("Scan failed. See python_scanner.log for details.")

        def _finish_scan(self, result):
            self._set_busy(False)
            if not isinstance(result, ScanResult):
                self.scan_status.text = "The analysis engine returned an invalid response."
                self.scan_status.color = C_RED
                return
            self.last_result = result
            self.findings = list(result.findings)
            self.progress.max = max(1, result.files_total)
            self.progress.value = result.files_scanned
            self.progress._update_bar()
            self._update_summary(result)
            if result.status is ScanStatus.CANCELLED:
                self.scan_status.text = "Scan cancelled. Results are incomplete."
                self.scan_status.color = C_ORANGE
            elif result.status is ScanStatus.COMPLETED_WITH_ISSUES:
                self.scan_status.text = "Scan finished with some checks unavailable."
                self.scan_status.color = C_ORANGE
            else:
                self.scan_status.text = "Scan completed successfully."
                self.scan_status.color = C_GREEN
            self.export_button.disabled = False
            self._render_findings()
            self._render_tool_status(result)
            self.go("results")
            self.home_files.value_label.text = str(result.files_scanned)
            self.home_findings.value_label.text = str(len(result.findings))
            self.home_latest.text = (
                f"{result.files_scanned} files scanned  •  {len(result.findings)} findings\n"
                f"{result.duration_seconds:.2f} sec  •  {result.status.value}"
            )

        def _update_summary(self, result):
            counts = result.count_by_severity()
            self.result_errors.value_label.text = str(counts[Severity.ERROR])
            self.result_warnings.value_label.text = str(counts[Severity.WARNING])
            self.result_info.value_label.text = str(counts[Severity.INFO])
            notes = result.tool_notes()
            self.results_summary.text = (
                f"Scanned {result.files_scanned} of {result.files_total} files  •  "
                f"{len(result.findings)} findings detected\n"
                f"Duration: {result.duration_seconds:.2f} sec  •  "
                f"Status: {result.status.value}"
                + (f"\n{notes}" if notes else "")
            )
            self.results_summary.color = C_TEXT

        # ----- Findings / detail ---------------------------------------
        def _clear_results(self):
            if not hasattr(self, "findings_list"):
                return
            self.results_summary.text = "No report available yet."
            self.results_summary.color = C_MUTED
            for metric in (self.result_errors, self.result_warnings, self.result_info):
                metric.value_label.text = "—"
            self.findings_list.clear_widgets()
            self.findings_list.add_widget(NeonLabel(text="No findings to display yet.",
                                                    size=11, color=C_MUTED, height=dp(48)))
            self.findings_count.text = "0 findings"
            self.tool_status_label.text = "Tool status will appear here after a scan."
            self.load_more_button.disabled = True

        def _on_filter(self, _spinner, value):
            self.active_filter = value
            self.visible_limit = 120
            self._render_findings()

        def _on_search(self, _widget, value):
            self.search_query = value.strip().lower()
            self.visible_limit = 120
            self._render_findings()

        def _filtered_findings(self):
            severity_map = {"All": "all", "Error": "error", "Warning": "warning", "Info": "info"}
            wanted = severity_map.get(self.active_filter, "all")
            results = []
            for finding in self.findings:
                if wanted != "all" and finding.severity.value != wanted:
                    continue
                haystack = " ".join((finding.tool, finding.rule_id, finding.file,
                                     finding.message, finding.category.value)).lower()
                if self.search_query and self.search_query not in haystack:
                    continue
                results.append(finding)
            return results

        def _render_findings(self):
            if not hasattr(self, "findings_list"):
                return
            self.findings_list.clear_widgets()
            matches = self._filtered_findings()
            shown = matches[:self.visible_limit]
            self.findings_count.text = f"Showing {len(shown)} of {len(matches)} findings"
            if not shown:
                message = "No findings match this filter." if self.findings else "No results yet."
                self.findings_list.add_widget(NeonLabel(text=message, size=11,
                                                        color=C_MUTED, height=dp(54)))
            else:
                for finding in shown:
                    self.findings_list.add_widget(self._finding_card(finding))
            self.load_more_button.disabled = len(matches) <= self.visible_limit

        def _load_more(self):
            self.visible_limit += 120
            self._render_findings()

        def _finding_card(self, finding):
            severity = finding.severity
            accent = C_RED if severity is Severity.ERROR else (
                C_ORANGE if severity is Severity.WARNING else C_BLUE)
            card = NeonSurface(orientation="vertical", padding=dp(12), spacing=dp(5),
                               size_hint_y=None, height=dp(112), fill=C_SURFACE)
            top = BoxLayout(size_hint_y=None, height=dp(24), spacing=dp(7))
            top.add_widget(NeonLabel(text=severity.value.upper(), size=9,
                                     color=accent, bold=True, height=dp(23)))
            top.add_widget(NeonLabel(text=f"{finding.tool}  •  {finding.rule_id}",
                                     size=9, color=C_MUTED, height=dp(23)))
            card.add_widget(top)
            card.add_widget(NeonLabel(text=finding.message, size=10,
                                      color=C_TEXT, height=dp(48)))
            location = finding.file + (f"  :  {finding.line}" if finding.line else "")
            card.add_widget(NeonLabel(text=location, size=9, color=C_MUTED,
                                      height=dp(20)))
            card.bind(on_touch_up=lambda widget, touch, item=finding:
                      self._open_finding(item) if widget.collide_point(*touch.pos) else None)
            return card

        def _suggestion(self, finding):
            suggestions = {
                "SEC-SHELL-TRUE": "Avoid shell=True when possible. Pass subprocess arguments as a list.",
                "SEC-OS-SHELL": "Do not pass untrusted data to shell commands. Prefer direct library APIs.",
                "SEC-PICKLE": "Only load fully trusted pickle data. Prefer a safer interchange format such as JSON for external data.",
                "SEC-DYNAMIC-EXEC": "Do not use eval/exec on external input. Validate input and implement the required logic explicitly.",
                "SEC-YAML-LOAD": "Use yaml.safe_load when parsing untrusted YAML.",
                "SEC-YAML-UNSAFE": "Replace unsafe YAML loading with yaml.safe_load.",
                "SEC-TLS-VERIFY-OFF": "Keep TLS certificate verification enabled.",
                "SEC-SSL-VERIFY-OFF": "Use the default SSL context with certificate validation enabled.",
                "SEC-WEAK-HASH": "Use modern algorithms for security-sensitive hashing. Use a dedicated password-hashing algorithm for passwords.",
                "SEC-TEMPFILE-MKTEMP": "Use tempfile.NamedTemporaryFile or tempfile.mkstemp instead.",
                "SEC-SQL-STRING-FORMAT": "Pass values as database parameters instead of formatting them into SQL strings.",
                "SEC-TAR-EXTRACT": "Validate archive member paths before extraction and allow only paths inside the intended destination.",
                "BUG-MUTABLE-DEFAULT": "Use None as the default and create a fresh list or dictionary inside the function.",
                "BUG-SILENT-EXCEPTION": "Log the error or catch only expected exceptions. A silent pass makes debugging difficult.",
                "BUG-IDENTITY-COMPARE": "Use == or != for value comparison. Reserve is for identity checks, such as comparison with None.",
                "BUG-DUPLICATE-DICT-KEY": "Remove or correct the duplicate key; the earlier value is silently overwritten.",
                "BUG-BLOCKING-SLEEP": "Use await asyncio.sleep(...) inside an async function.",
                "QUALITY-HTTP-NO-TIMEOUT": "Set a timeout for network requests to prevent indefinite waiting.",
                "QUALITY-URLLIB-NO-TIMEOUT": "Set a bounded timeout for urlopen.",
                "QUALITY-ASSERT-STATEMENT": "Use if/raise for required input validation; assert statements may be removed with -O.",
                "QUALITY-FILE-ENCODING": "Specify a text-file encoding, usually encoding='utf-8'.",
                "QUALITY-NONE-COMPARE": "Use value is None or value is not None.",
                "QUALITY-TOO-MANY-ARGS": "Group related parameters in a dataclass or configuration object.",
                "QUALITY-LONG-FUNCTION": "Split the function into smaller functions with clear responsibilities.",
                "QUALITY-COMPLEX-FUNCTION": "Simplify conditional branches and move independent logic into helper functions.",
                "QUALITY-VERY-COMPLEX-FUNCTION": "Break the function into clear paths and add focused tests for important branches.",
                "QUALITY-PRINT-DEBUG": "Use logging for diagnostic events or remove temporary debug output.",
            }
            return suggestions.get(finding.rule_id,
                                   "Review the reported line. Some static-analysis findings may require manual confirmation.")

        def _open_finding(self, finding):
            content = BoxLayout(orientation="vertical", padding=dp(14), spacing=dp(9))
            scroll = ScrollView(do_scroll_x=False, bar_width=dp(3))
            details = BoxLayout(orientation="vertical", size_hint_y=None,
                                spacing=dp(8), padding=(0, 0, 0, dp(10)))
            details.bind(minimum_height=details.setter("height"))
            accent = C_RED if finding.severity is Severity.ERROR else (
                C_ORANGE if finding.severity is Severity.WARNING else C_BLUE)
            details.add_widget(NeonLabel(text=f"{finding.severity.value.upper()}  •  {finding.rule_id}",
                                         size=13, color=accent, bold=True, height=dp(32)))
            details.add_widget(NeonLabel(text=finding.message, size=12,
                                         color=C_TEXT, height=dp(76)))
            details.add_widget(NeonLabel(
                text=f"File: {finding.file}\nLine: {finding.line if finding.line else 'Unknown'}\nTool: {finding.tool}\nCategory: {finding.category.value}\nConfidence: {finding.confidence.value}",
                size=10, color=C_MUTED, height=dp(104)))
            details.add_widget(NeonLabel(text="SUGGESTED FIX", size=12,
                                         color=C_ACCENT, bold=True, height=dp(28)))
            details.add_widget(NeonLabel(text=self._suggestion(finding), size=11,
                                         color=C_TEXT, height=dp(72)))
            if finding.snippet:
                details.add_widget(NeonLabel(text="CODE SNIPPET", size=11,
                                             color=C_ACCENT, bold=True, height=dp(26)))
                details.add_widget(NeonLabel(text=finding.snippet, size=10,
                                             color=C_MUTED, height=dp(66)))
            scroll.add_widget(details)
            content.add_widget(scroll)
            popup = Popup(title="Finding Details", content=content,
                          size_hint=(0.94, 0.82), separator_color=C_ACCENT)
            content.add_widget(self._button("CLOSE", popup.dismiss,
                                            secondary=True, height=44))
            self._finding_popup = popup
            popup.open()

        def _render_tool_status(self, result):
            state_names = {
                ToolState.OK: "Available",
                ToolState.MISSING: "Not installed",
                ToolState.SKIPPED: "Not run",
                ToolState.TIMEOUT: "Timed out",
                ToolState.FAILED: "Failed",
            }
            lines = []
            for tool in result.tool_statuses:
                line = f"{tool.name}: {state_names.get(tool.state, tool.state.value)}"
                if tool.version:
                    line += f"  ({tool.version})"
                if tool.detail and tool.state is not ToolState.OK:
                    line += f"\n{redact_text(tool.detail)[:160]}"
                lines.append(line)
            self.tool_status_label.text = "\n".join(lines) if lines else "Tool status unavailable."

        # ----- Report export --------------------------------------------
        def export_report(self):
            if not self.last_result:
                self._toast("There is no report to export yet.")
                return
            form = BoxLayout(orientation="vertical", padding=dp(14), spacing=dp(10))
            name_field = TextInput(text="python_scanner_report.json", multiline=False,
                                   size_hint_y=None, height=dp(46),
                                   background_normal="", background_active="",
                                   background_color=C_SURFACE_2,
                                   foreground_color=C_TEXT, cursor_color=C_ACCENT,
                                   font_size=sp(12))
            form.add_widget(NeonLabel(text="Report filename", size=11, color=C_MUTED))
            form.add_widget(name_field)
            form.add_widget(NeonLabel(
                text="The report may contain messages and masked code snippets. Review it before sharing.",
                size=10, color=C_MUTED, height=dp(42)))
            popup = Popup(title="Export Report", content=form,
                          size_hint=(0.92, 0.40), separator_color=C_ACCENT)
            actions = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(48))

            def save(*_):
                name = Path(name_field.text.strip()).name
                if not name:
                    self._toast("Enter a filename.")
                    return
                if not name.lower().endswith(".json"):
                    name += ".json"
                destination_dir = _writable_report_folder()
                destination = destination_dir / name
                try:
                    write_json_report(self.last_result, destination)
                except Exception as exc:
                    _write_startup_log("REPORT_EXPORT_FAILED\n" + traceback.format_exc())
                    self._toast(f"Report export failed: {type(exc).__name__}")
                else:
                    popup.dismiss()
                    self._toast(f"Report saved:\n{destination}")

            actions.add_widget(self._button("CANCEL", popup.dismiss, secondary=True))
            actions.add_widget(self._button("SAVE", save))
            form.add_widget(actions)
            popup.open()

        # ----- Small UX helpers ----------------------------------------
        def _toast(self, message):
            try:
                if self._toast_popup:
                    self._toast_popup.dismiss()
                label = NeonLabel(text=str(message), size=11, color=C_TEXT,
                                  halign="center", height=dp(74))
                popup = Popup(title=APP_TITLE, content=label,
                              size_hint=(0.90, 0.30), separator_color=C_ACCENT)
                self._toast_popup = popup
                popup.open()
                Clock.schedule_once(lambda _dt: popup.dismiss(), 3.0)
            except Exception:
                _write_startup_log("TOAST_FAILED\n" + traceback.format_exc())

        def on_pause(self):
            return True

        def on_stop(self):
            if self.task and self.task.is_alive():
                self.task.cancel_event.set()


def _writable_report_folder() -> Path:
    for folder in (Path("/storage/emulated/0/Download"), Path.home(), Path.cwd()):
        try:
            if folder.is_dir() and os.access(str(folder), os.W_OK):
                return folder
        except OSError:
            continue
    return Path.cwd()


def main() -> int:
    if not KIVY_AVAILABLE:
        _write_startup_log("KIVY_NOT_AVAILABLE\n" + KIVY_IMPORT_ERROR)
        print("Kivy must be installed and enabled in Pydroid 3 to run the mobile interface.\n"
              + KIVY_IMPORT_ERROR, file=sys.stderr)
        return 2
    try:
        PythonScannerApp().run()
        return 0
    except Exception:
        detail = traceback.format_exc()
        _write_startup_log("APPLICATION_START_FAILED\n" + detail)
        print("Python Scanner could not start. See python_scanner.log.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

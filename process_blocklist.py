"""
hapara.fail AdBlock Plus Blocklist Validator & Metadata Updater
================================================================
Validates AdBlock Plus format blocklists, emits GitHub Actions annotations,
writes a step summary, and atomically updates file metadata on success.

Usage:
  python validate_blocklist.py [file ...]
  python validate_blocklist.py blocklist.txt --dry-run
  python validate_blocklist.py *.txt --fix       # auto-fix safe issues
  python validate_blocklist.py --strict          # warnings become errors
  python validate_blocklist.py --sort            # sort rules alphabetically
  python validate_blocklist.py --stats           # print detailed statistics
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# ANSI / GitHub Actions output helpers
# ──────────────────────────────────────────────────────────────────────────────

_IN_GHA = "GITHUB_ACTIONS" in os.environ


class Color:
    HEADER  = '\033[95m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'

    @staticmethod
    def strip(s: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', s)


def _c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes (skips if not a TTY and not forced)."""
    if not sys.stdout.isatty() and not _IN_GHA:
        return text
    return ''.join(codes) + text + Color.ENDC


def _gha_escape(msg: str) -> str:
    """Escape a string for GitHub Actions workflow commands."""
    return msg.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def gha_annotation(
    level: str,
    file: str,
    line: int,
    msg: str,
    *,
    title: str = "",
    end_line: int = 0,
    col: int = 0,
    end_col: int = 0,
) -> None:
    """Emit a GitHub Actions annotation with optional title and column info."""
    if not _IN_GHA:
        return
    props = [f"file={file}", f"line={line}"]
    if end_line:
        props.append(f"endLine={end_line}")
    if col:
        props.append(f"col={col}")
    if end_col:
        props.append(f"endColumn={end_col}")
    if title:
        props.append(f"title={_gha_escape(title)}")
    print(f"::{level} {','.join(props)}::{_gha_escape(msg)}")


def gha_group(name: str, open_: bool = True) -> None:
    """Open or close a foldable log group in GitHub Actions."""
    if not _IN_GHA:
        return
    if open_:
        print(f"::group::{name}")
    else:
        print("::endgroup::")


def gha_set_output(name: str, value: Any) -> None:
    """Write a step output variable via GITHUB_OUTPUT (modern approach)."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    # Handle multi-line values with the heredoc delimiter
    str_value = str(value)
    with open(output_path, "a", encoding="utf-8") as f:
        if '\n' in str_value:
            delimiter = f"ghadelimiter_{hash(str_value) & 0xFFFFFFFF:08x}"
            f.write(f"{name}<<{delimiter}\n{str_value}\n{delimiter}\n")
        else:
            f.write(f"{name}={str_value}\n")


def gha_set_env(name: str, value: str) -> None:
    """Set an environment variable for subsequent workflow steps via GITHUB_ENV."""
    env_path = os.environ.get("GITHUB_ENV")
    if not env_path:
        return
    with open(env_path, "a", encoding="utf-8") as f:
        if '\n' in value:
            delimiter = f"ghadelimiter_{hash(value) & 0xFFFFFFFF:08x}"
            f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            f.write(f"{name}={value}\n")


def write_step_summary(md: str) -> None:
    """Append markdown to the GitHub Actions step summary."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(md + "\n")


# ──────────────────────────────────────────────────────────────────────────────
# Rule classification
# ──────────────────────────────────────────────────────────────────────────────

# Valid AdBlock option modifiers after `$`
VALID_OPTIONS: Set[str] = {
    "script", "image", "stylesheet", "object", "xmlhttprequest", "object-subrequest",
    "subdocument", "document", "elemhide", "generichide", "genericblock", "other",
    "third-party", "first-party", "~third-party", "~first-party", "all",
    "popup", "media", "font", "websocket", "webrtc", "ping", "csp",
    "important", "badfilter", "redirect", "redirect-rule", "denyallow",
    "domain", "app", "network", "permissions", "stealth", "cookie",
    "removeparam", "removeheader", "header", "method", "to", "from",
    "match-case", "replace", "urltransform",
    # common shorthand
    "3p", "1p", "~3p", "~1p", "xhr",
}

# Known TLDs for domain validation (subset of common ones)
_KNOWN_TLDS: Set[str] = {
    "com", "net", "org", "io", "co", "us", "uk", "de", "fr", "jp", "ru",
    "cn", "br", "in", "au", "ca", "it", "es", "nl", "se", "no", "fi",
    "info", "biz", "me", "tv", "cc", "xyz", "online", "site", "app",
    "dev", "tech", "cloud", "ai", "gg", "ly", "to", "sh", "fm", "gg",
    "edu", "gov", "mil", "int",
}

# Regex to identify rule categories
_NETWORK_BLOCK  = re.compile(r'^\|\|.+')
_NETWORK_ALLOW  = re.compile(r'^@@\|\|.+')
_COSMETIC       = re.compile(r'^.+##.+')
_COSMETIC_ALLOW = re.compile(r'^.+#@#.+')
_EXTENDED_CSS   = re.compile(r'^.+#\?#.+')
_SCRIPTLET      = re.compile(r'^.+#\$#.+')
_HTML_FILTER    = re.compile(r'^.+\$\$.*')
_COMMENT        = re.compile(r'^[!#]')
_ADBLOCK_HDR    = re.compile(r'^\[Adblock', re.IGNORECASE)

# Header metadata patterns
HEADER_PATTERNS: Dict[str, Pattern] = {
    'count':    re.compile(r'^! Number of entries:.*',  re.IGNORECASE),
    'modified': re.compile(r'^! Last modified:.*',      re.IGNORECASE),
    'version':  re.compile(r'^! Version:.*',            re.IGNORECASE),
}

# Pattern for detecting IP address rules (hosts-file format mixed in)
_IP_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+\S+')

# Pattern for detecting regex rules
_REGEX_RULE = re.compile(r'^/.+/$')


def classify_rule(line: str) -> Optional[str]:
    """
    Return a human-readable category string, or None if not a rule.
    Order matters -- more specific patterns first.
    """
    if not line or _COMMENT.match(line) or _ADBLOCK_HDR.match(line):
        return None
    if _NETWORK_ALLOW.match(line):
        return "allow"
    if _NETWORK_BLOCK.match(line):
        return "block"
    if _COSMETIC_ALLOW.match(line):
        return "cosmetic-allow"
    if _SCRIPTLET.match(line):
        return "scriptlet"
    if _EXTENDED_CSS.match(line):
        return "extended-css"
    if _COSMETIC.match(line):
        return "cosmetic"
    if _REGEX_RULE.match(line):
        return "regex"
    return "other"


def is_rule(line: str) -> bool:
    return classify_rule(line) is not None


def extract_domain(rule: str) -> Optional[str]:
    """Extract the domain from a network block/allow rule like ||domain.com^."""
    if rule.startswith('@@||'):
        body = rule[4:]
    elif rule.startswith('||'):
        body = rule[2:]
    else:
        return None
    # Strip trailing ^ and $options
    body = body.split('$')[0]
    body = body.rstrip('^').rstrip('*')
    # Only return if it looks like a domain
    if body and '/' not in body and ' ' not in body:
        return body.lower()
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Diagnostic containers
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Diagnostic:
    level: str   # "error" | "warning" | "notice"
    line: int
    message: str
    fixable: bool = False
    code: str = ""  # short error code, e.g. "E001"


@dataclass
class ValidationResult:
    file: Path
    diagnostics: List[Diagnostic] = field(default_factory=list)
    rule_counts: Dict[str, int]   = field(default_factory=dict)
    total_lines: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    fixed_count: int = 0
    tld_distribution: Dict[str, int] = field(default_factory=dict)
    domain_list: List[str] = field(default_factory=list)

    @property
    def errors(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.level == "error"]

    @property
    def warnings(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.level == "warning"]

    @property
    def notices(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.level == "notice"]

    @property
    def total_rules(self) -> int:
        return sum(self.rule_counts.values())

    def is_valid(self) -> bool:
        return len(self.errors) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Validator
# ──────────────────────────────────────────────────────────────────────────────

class BlocklistValidator:
    """
    Stateful validator. Call .validate_line() for each line, then inspect
    .result for accumulated diagnostics and counts.
    """

    def __init__(self, strict: bool = False):
        self.strict = strict
        self.result = ValidationResult(file=Path())
        self._seen_rules: Set[str] = set()
        self._blocked_domains: Set[str] = set()
        self._first_rule_seen = False
        self._last_line_blank = False
        self._consecutive_blanks = 0

    def reset(self, file: Path) -> None:
        self.result = ValidationResult(file=file)
        self._seen_rules = set()
        self._blocked_domains = set()
        self._first_rule_seen = False
        self._last_line_blank = False
        self._consecutive_blanks = 0

    # -- helpers ---------------------------------------------------------------

    def _diag(
        self,
        level: str,
        line_num: int,
        msg: str,
        fixable: bool = False,
        code: str = "",
    ) -> None:
        effective_level = "error" if (level == "warning" and self.strict) else level
        self.result.diagnostics.append(
            Diagnostic(effective_level, line_num, msg, fixable, code)
        )

    # -- per-line validation ---------------------------------------------------

    def validate_line(self, raw_line: str, line_num: int) -> None:
        self.result.total_lines += 1
        line = raw_line.rstrip('\n').rstrip('\r')

        # -- Universal checks (apply to every line) ----------------------------

        # Check: Tab characters
        if '\t' in line:
            self._diag("error", line_num,
                       "Contains tab character (\\t). Use spaces.",
                       fixable=True, code="E001")

        # Check: Non-printable control characters
        try:
            line.encode('ascii')
        except UnicodeEncodeError:
            if any(ord(c) < 32 and c not in ('\t',) for c in line):
                self._diag("error", line_num,
                           "Contains non-printable control characters.",
                           code="E002")

        # Check: Overly long lines (>500 chars hints at a mistake)
        if len(line) > 500:
            self._diag("warning", line_num,
                       f"Unusually long line ({len(line)} chars). Verify it's correct.",
                       code="W001")

        # Check: Consecutive blank lines (>2 is sloppy)
        stripped = line.strip()
        if not stripped:
            self.result.blank_lines += 1
            self._consecutive_blanks += 1
            if self._consecutive_blanks > 2:
                self._diag("warning", line_num,
                           "Excessive consecutive blank lines.",
                           fixable=True, code="W002")
            self._last_line_blank = True
            return

        self._consecutive_blanks = 0
        self._last_line_blank = False

        # Track comment lines
        if _COMMENT.match(stripped) or _ADBLOCK_HDR.match(stripped):
            self.result.comment_lines += 1

        # Check: Hosts-file format mixed in (0.0.0.0 or 127.0.0.1)
        if _IP_RULE.match(stripped):
            self._diag("error", line_num,
                       f"Hosts-file format detected: '{stripped}'. Convert to AdBlock syntax (||domain^).",
                       code="E003")
            return

        # Skip non-rules for rule-specific checks
        if not is_rule(stripped):
            return

        self._first_rule_seen = True
        category = classify_rule(stripped)

        # -- Rule-specific checks ----------------------------------------------

        # Check: Trailing whitespace on a rule
        if line != line.rstrip():
            self._diag("warning", line_num,
                       "Rule has trailing whitespace.",
                       fixable=True, code="W003")

        # Check: Protocol in network rule
        if category in ("block", "allow") and '://' in stripped:
            self._diag("error", line_num,
                       "Network rule contains protocol (http/https). Remove '://'.",
                       code="E004")

        # Check: Spaces inside a rule (invalid in network rules)
        if category in ("block", "allow") and ' ' in stripped:
            self._diag("error", line_num,
                       f"Rule contains illegal spaces: '{stripped}'",
                       code="E005")

        # Check: Empty / stub rules
        if stripped in ('||', '@@', '||^', '@@^', '##', '#@#', '##.', '#@#.'):
            self._diag("error", line_num,
                       f"Rule is empty or incomplete: '{stripped}'",
                       code="E006")
            return

        # Check: Wildcard-only network rule (blocks/allows everything)
        if stripped in ('*', '||*^', '@@*', '@@||*^'):
            self._diag("error", line_num,
                       f"Overly broad wildcard rule: '{stripped}' -- this is almost always a mistake.",
                       code="E007")

        # Check: Validate $options modifier
        if '$' in stripped and category in ("block", "allow"):
            self._validate_options(stripped, line_num)

        # Check: Duplicate detection (normalised to lowercase for domains)
        normalised = stripped.lower() if category in ("block", "allow") else stripped
        if normalised in self._seen_rules:
            self._diag("error", line_num,
                       f"Duplicate rule: '{stripped}'",
                       code="E008")
        else:
            self._seen_rules.add(normalised)
            self.result.rule_counts[category] = \
                self.result.rule_counts.get(category, 0) + 1

        # Check: Missing separator ^ on domain rules (warning)
        if (category == "block"
                and stripped.startswith('||')
                and '$' not in stripped
                and not stripped.endswith('^')
                and '/' not in stripped[2:]
                and '*' not in stripped[2:]):
            self._diag("warning", line_num,
                       f"Network rule missing '^' separator at end: '{stripped}'",
                       fixable=True, code="W004")

        # Check: Redundancy -- ||sub.domain^ when ||domain^ already exists
        if category == "block" and stripped.endswith('^') and '$' not in stripped:
            domain = stripped[2:-1]  # strip || and ^
            parts = domain.split('.')
            for i in range(1, len(parts) - 1):
                parent = '.'.join(parts[i:])
                if parent in self._blocked_domains:
                    self._diag("notice", line_num,
                               f"Possibly redundant: '||{domain}^' is a subdomain of already-blocked '||{parent}^'.",
                               code="N001")
                    break
            self._blocked_domains.add(domain)

        # Check: Cosmetic rule with empty selector
        if category in ("cosmetic", "cosmetic-allow"):
            sep = '##' if category == "cosmetic" else '#@#'
            parts = stripped.split(sep, 1)
            if len(parts) == 2 and not parts[1].strip():
                self._diag("error", line_num,
                           f"Cosmetic rule has empty selector after '{sep}'.",
                           code="E009")

        # Check: Domain with consecutive dots (e.g. ||example..com^)
        if category in ("block", "allow"):
            domain = extract_domain(stripped)
            if domain:
                if '..' in domain:
                    self._diag("error", line_num,
                               f"Domain contains consecutive dots: '{domain}'",
                               code="E010")
                # Check: Domain with trailing dot
                if domain.endswith('.'):
                    self._diag("warning", line_num,
                               f"Domain has trailing dot: '{domain}'",
                               code="W005")
                # Track TLD distribution
                tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
                if tld:
                    self.result.tld_distribution[tld] = \
                        self.result.tld_distribution.get(tld, 0) + 1
                self.result.domain_list.append(domain)

        # Check: Regex rule validation
        if category == "regex":
            inner = stripped[1:-1]
            try:
                re.compile(inner)
            except re.error as exc:
                self._diag("error", line_num,
                           f"Invalid regex pattern: {exc}",
                           code="E011")

    def _validate_options(self, rule: str, line_num: int) -> None:
        """Validate the $option,list part of a network rule."""
        dollar_idx = rule.rfind('$')
        if dollar_idx == -1:
            return
        options_str = rule[dollar_idx + 1:]
        raw_options = [o.strip() for o in options_str.split(',') if o.strip()]

        for opt in raw_options:
            key = opt.lstrip('~').split('=')[0].lower()
            if key and key not in VALID_OPTIONS:
                self._diag("warning", line_num,
                           f"Unknown or non-standard option '${opt}'. "
                           "Verify it's supported by your target adblocker.",
                           code="W006")

        # Check for conflicting options
        option_keys = [o.lstrip('~').split('=')[0].lower() for o in raw_options]
        if 'third-party' in option_keys and '~third-party' in option_keys:
            self._diag("error", line_num,
                       "Conflicting options: 'third-party' and '~third-party' on same rule.",
                       code="E012")
        if 'first-party' in option_keys and '~first-party' in option_keys:
            self._diag("error", line_num,
                       "Conflicting options: 'first-party' and '~first-party' on same rule.",
                       code="E013")


# ──────────────────────────────────────────────────────────────────────────────
# Sorting / deduplication
# ──────────────────────────────────────────────────────────────────────────────

def sort_rules(lines: List[str]) -> List[str]:
    """
    Sort the blocklist: preserve the header block (comments at the top),
    then sort rules alphabetically (case-insensitive), grouping by type.
    Blank lines between sections are normalised.
    """
    header: List[str] = []
    rules: List[str] = []
    in_header = True

    for line in lines:
        stripped = line.rstrip('\n').rstrip('\r').strip()
        if in_header and (not stripped or _COMMENT.match(stripped) or _ADBLOCK_HDR.match(stripped)):
            header.append(line)
        else:
            in_header = False
            if stripped:  # skip blank lines between rules
                rules.append(line)

    # Sort rules case-insensitively
    rules.sort(key=lambda r: r.strip().lower())

    # Rebuild the file
    result = list(header)
    if result and result[-1].strip():
        result.append('\n')
    result.extend(rules)
    if result and not result[-1].endswith('\n'):
        result.append('\n')
    return result


def dedup_lines(lines: List[str]) -> Tuple[List[str], int]:
    """Remove exact duplicate rules while preserving header/comments."""
    seen: Set[str] = set()
    result: List[str] = []
    removed = 0

    for line in lines:
        stripped = line.rstrip('\n').rstrip('\r').strip()
        if not is_rule(stripped):
            result.append(line)
            continue
        normalised = stripped.lower()
        if normalised in seen:
            removed += 1
        else:
            seen.add(normalised)
            result.append(line)

    return result, removed


# ──────────────────────────────────────────────────────────────────────────────
# File processing
# ──────────────────────────────────────────────────────────────────────────────

def get_timestamps() -> Tuple[str, str]:
    """Return (human timestamp, version string) in UTC."""
    now = datetime.now(timezone.utc)
    return (
        now.strftime('%d %b %Y %H:%M UTC'),
        now.strftime('%Y.%m%d.%H%M'),
    )


def file_checksum(path: Path) -> str:
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()[:12]


def apply_fixes(lines: List[str], diags: List[Diagnostic]) -> Tuple[List[str], int]:
    """
    Apply safe auto-fixes in-place. Returns (new_lines, fix_count).
    Currently fixes: trailing whitespace, missing ^ separator, tab->space,
    excessive blank lines.
    """
    fixed = list(lines)
    fix_count = 0
    fixable_lines = {d.line for d in diags if d.fixable}

    consecutive_blanks = 0
    for idx in range(len(fixed)):
        line_num = idx + 1
        original = fixed[idx]
        line = original

        # Fix excessive consecutive blank lines
        if not line.strip():
            consecutive_blanks += 1
            if consecutive_blanks > 2 and line_num in fixable_lines:
                fixed[idx] = None  # mark for removal
                fix_count += 1
                continue
        else:
            consecutive_blanks = 0

        if line_num not in fixable_lines:
            continue

        # Fix tabs -> spaces
        if '\t' in line:
            line = line.replace('\t', '    ')

        # Fix trailing whitespace (preserve newline)
        stripped_no_nl = line.rstrip('\n').rstrip('\r')
        nl = line[len(stripped_no_nl):]
        line = stripped_no_nl.rstrip() + nl

        # Fix missing ^ on block rules
        rule = line.rstrip('\n').rstrip('\r').strip()
        if (rule.startswith('||')
                and not rule.endswith('^')
                and '$' not in rule
                and '/' not in rule[2:]
                and '*' not in rule[2:]):
            line = rule + '^' + nl

        if line != original:
            fixed[idx] = line
            fix_count += 1

    # Remove None entries (excessive blank lines)
    fixed = [l for l in fixed if l is not None]

    return fixed, fix_count


def process_file(
    file_path: Path,
    *,
    dry_run: bool = False,
    fix: bool = False,
    strict: bool = False,
    sort: bool = False,
    stats: bool = False,
    rel_path: Optional[str] = None,
) -> ValidationResult:
    """
    Full pipeline: read -> validate -> (optionally fix/sort) -> write headers.
    Returns the ValidationResult regardless of pass/fail.
    """
    ann_path = rel_path or str(file_path)

    if not file_path.exists():
        print(_c(f"[ERR] File not found: {file_path}", Color.RED, Color.BOLD))
        sys.exit(1)

    # Per-file log group in GHA for cleaner output
    gha_group(f"Validating {file_path.name}")
    t_start = time.monotonic()

    print(_c(f"\n>> Processing: {file_path.name}", Color.HEADER, Color.BOLD))
    checksum_before = file_checksum(file_path)
    print(f"   SHA-256: {checksum_before}")

    validator = BlocklistValidator(strict=strict)
    validator.reset(file_path)

    # -- Pass 1: read & validate -----------------------------------------------
    try:
        raw_lines = file_path.read_text(encoding='utf-8').splitlines(keepends=True)
    except UnicodeDecodeError:
        print(_c("  [ERR] File is not valid UTF-8.", Color.RED))
        sys.exit(1)

    for i, line in enumerate(raw_lines, 1):
        validator.validate_line(line, i)

    result = validator.result

    # -- Emit GHA annotations --------------------------------------------------
    for d in result.diagnostics:
        title = f"[{d.code}]" if d.code else "Blocklist Validation"
        gha_annotation(d.level, ann_path, d.line, d.message, title=title)

    # -- Console output --------------------------------------------------------
    if result.notices:
        print(_c(f"\n  Notices ({len(result.notices)}):", Color.BLUE))
        for n in result.notices:
            tag = f" [{n.code}]" if n.code else ""
            print(f"    line {n.line:>5}: {n.message}{tag}")

    if result.warnings:
        print(_c(f"\n  Warnings ({len(result.warnings)}):", Color.YELLOW))
        for w in result.warnings:
            fix_tag = _c(" [auto-fixable]", Color.DIM) if w.fixable else ""
            tag = f" [{w.code}]" if w.code else ""
            print(f"    line {w.line:>5}: {w.message}{tag}{fix_tag}")

    if result.errors:
        print(_c(f"\n  Errors ({len(result.errors)}):", Color.RED, Color.BOLD))
        for e in result.errors:
            fix_tag = _c(" [auto-fixable]", Color.DIM) if e.fixable else ""
            tag = f" [{e.code}]" if e.code else ""
            print(f"    line {e.line:>5}: {e.message}{tag}{fix_tag}")

    # -- Print rule-type breakdown ---------------------------------------------
    print(_c(f"\n  Rule breakdown:", Color.BLUE))
    labels = {
        "block": "Network block",
        "allow": "Network allow",
        "cosmetic": "Cosmetic hide",
        "cosmetic-allow": "Cosmetic allow",
        "extended-css": "Extended CSS",
        "scriptlet": "Scriptlet",
        "regex": "Regex",
        "other": "Other",
    }
    for key, label in labels.items():
        count = result.rule_counts.get(key, 0)
        if count:
            print(f"    {label:<18} {count:>6}")
    print(f"    {'Total':<18} {result.total_rules:>6}")
    print(f"    {'Lines':<18} {result.total_lines:>6}  "
          f"(blank: {result.blank_lines}, comments: {result.comment_lines})")

    # -- Detailed statistics ---------------------------------------------------
    if stats and result.tld_distribution:
        print(_c(f"\n  Top TLDs:", Color.CYAN))
        sorted_tlds = sorted(result.tld_distribution.items(),
                             key=lambda x: x[1], reverse=True)
        for tld, count in sorted_tlds[:15]:
            bar = "#" * min(count, 40)
            print(f"    .{tld:<8} {count:>5}  {bar}")

    # -- Fail fast if errors exist (before fix attempt) -------------------------
    non_fixable_errors = [e for e in result.errors if not e.fixable]
    fixable_errors     = [e for e in result.errors if e.fixable]

    if non_fixable_errors:
        print(_c(
            f"\n  [FAIL] Validation FAILED -- {len(non_fixable_errors)} non-fixable error(s). "
            "Resolve them manually and re-run.",
            Color.RED, Color.BOLD,
        ))
        return result

    # -- Auto-fix pass ---------------------------------------------------------
    working_lines = list(raw_lines)
    if fix and (fixable_errors or [d for d in result.warnings if d.fixable]):
        fixable_diags = [d for d in result.diagnostics if d.fixable]
        working_lines, result.fixed_count = apply_fixes(raw_lines, fixable_diags)
        print(_c(f"\n  Auto-fixed {result.fixed_count} line(s).", Color.GREEN))

    elif fixable_errors and not fix:
        print(_c(
            f"\n  {len(fixable_errors)} error(s) are auto-fixable. "
            "Re-run with --fix to apply them.",
            Color.YELLOW,
        ))
        return result  # still a failure without --fix

    # -- Sort pass (optional) --------------------------------------------------
    if sort:
        working_lines = sort_rules(working_lines)
        print(_c("  Rules sorted alphabetically.", Color.GREEN))

    # -- Dedup pass (when --fix is active) -------------------------------------
    if fix:
        working_lines, dedup_count = dedup_lines(working_lines)
        if dedup_count:
            print(_c(f"  Removed {dedup_count} duplicate rule(s).", Color.GREEN))
            result.fixed_count += dedup_count

    # -- Success ---------------------------------------------------------------
    ts_str, ver_str = get_timestamps()
    print(_c(f"\n  [OK] Validation passed!", Color.GREEN, Color.BOLD))
    print(f"    Version: {ver_str}  |  Entries: {result.total_rules}")

    if dry_run:
        print(_c("  (dry run -- skipping file write)", Color.BLUE))
        return result

    # -- Pass 2: atomic header update ------------------------------------------
    temp_dir = file_path.parent
    updates_made = 0

    try:
        with NamedTemporaryFile(
            mode='w', encoding='utf-8', delete=False, dir=temp_dir
        ) as tmp:
            tmp_path = Path(tmp.name)
            for line in working_lines:
                out = line
                if HEADER_PATTERNS['count'].match(line):
                    out = f"! Number of entries: {result.total_rules}\n"
                    updates_made += 1
                elif HEADER_PATTERNS['modified'].match(line):
                    out = f"! Last modified: {ts_str}\n"
                    updates_made += 1
                elif HEADER_PATTERNS['version'].match(line):
                    out = f"! Version: {ver_str}\n"
                    updates_made += 1
                tmp.write(out)

        shutil.move(str(tmp_path), str(file_path))

        if updates_made:
            checksum_after = file_checksum(file_path)
            print(_c(f"  [OK] File updated ({updates_made} header(s) refreshed).", Color.GREEN))
            print(f"   SHA-256: {checksum_after}")
        else:
            print(_c(
                "  [WARN] No metadata headers (! Number of entries / ! Last modified / ! Version) "
                "found to update.",
                Color.YELLOW,
            ))

    except Exception as exc:
        print(_c(f"  [ERR] Write error: {exc}", Color.RED))
        if 'tmp_path' in locals() and tmp_path.exists():
            tmp_path.unlink()
        sys.exit(1)

    elapsed = time.monotonic() - t_start
    print(f"   Completed in {elapsed:.2f}s")
    gha_group("", open_=False)  # close per-file group

    return result


# ──────────────────────────────────────────────────────────────────────────────
# GitHub Step Summary
# ──────────────────────────────────────────────────────────────────────────────

def build_step_summary(
    results: List[ValidationResult],
    failed_files: List[Path],
    elapsed: float = 0.0,
) -> str:
    """Generate a rich Markdown step summary for GitHub Actions."""
    lines: List[str] = []
    total_rules = sum(r.total_rules for r in results)
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)
    total_notices = sum(len(r.notices) for r in results)
    total_fixed = sum(r.fixed_count for r in results)
    overall_pass = len(failed_files) == 0

    # -- Header ----------------------------------------------------------------
    status_badge = "PASSED" if overall_pass else "FAILED"
    lines.append(f"## Blocklist Validation: {status_badge}\n")

    # Quick stats line
    parts = [
        f"**{len(results)}** file(s)",
        f"**{total_rules}** rules",
    ]
    if total_errors:
        parts.append(f"**{total_errors}** error(s)")
    if total_warnings:
        parts.append(f"**{total_warnings}** warning(s)")
    if total_fixed:
        parts.append(f"**{total_fixed}** auto-fixed")
    if elapsed:
        parts.append(f"{elapsed:.2f}s")
    lines.append(" | ".join(parts) + "\n")

    # -- Per-file overview table ------------------------------------------------
    lines.append("### File Overview\n")
    lines.append("| Status | File | Entries | Errors | Warnings | Notices | Fixed |")
    lines.append("|:------:|------|--------:|-------:|---------:|--------:|------:|")
    for r in results:
        status = "Pass" if r.is_valid() else "FAIL"
        lines.append(
            f"| {status} "
            f"| `{r.file.name}` "
            f"| {r.total_rules} "
            f"| {len(r.errors)} "
            f"| {len(r.warnings)} "
            f"| {len(r.notices)} "
            f"| {r.fixed_count} |"
        )

    # -- Rule breakdown table --------------------------------------------------
    lines.append("\n### Rule Breakdown\n")
    labels = {
        "block": "Network block",
        "allow": "Network allow",
        "cosmetic": "Cosmetic hide",
        "cosmetic-allow": "Cosmetic allow",
        "extended-css": "Extended CSS",
        "scriptlet": "Scriptlet",
        "regex": "Regex",
        "other": "Other",
    }
    # Aggregate across all files
    agg_counts: Dict[str, int] = {}
    for r in results:
        for k, v in r.rule_counts.items():
            agg_counts[k] = agg_counts.get(k, 0) + v

    lines.append("| Category | Count |")
    lines.append("|----------|------:|")
    for key, label in labels.items():
        count = agg_counts.get(key, 0)
        if count:
            lines.append(f"| {label} | {count} |")
    lines.append(f"| **Total** | **{total_rules}** |")

    # -- TLD distribution (collapsible) ----------------------------------------
    agg_tlds: Dict[str, int] = {}
    for r in results:
        for tld, count in r.tld_distribution.items():
            agg_tlds[tld] = agg_tlds.get(tld, 0) + count
    if agg_tlds:
        sorted_tlds = sorted(agg_tlds.items(), key=lambda x: x[1], reverse=True)
        lines.append("\n<details>")
        lines.append("<summary>Top TLDs</summary>\n")
        lines.append("| TLD | Count |")
        lines.append("|-----|------:|")
        for tld, count in sorted_tlds[:20]:
            lines.append(f"| `.{tld}` | {count} |")
        lines.append("\n</details>")

    # -- Error detail (collapsible per file) -----------------------------------
    for r in results:
        if r.errors:
            lines.append(f"\n<details open>")
            lines.append(f"<summary>Errors in <code>{r.file.name}</code> ({len(r.errors)})</summary>\n")
            lines.append("| Line | Code | Message |")
            lines.append("|-----:|------|---------|")
            for e in r.errors[:50]:
                escaped_msg = e.message.replace('|', '\\|')
                lines.append(f"| {e.line} | `{e.code}` | {escaped_msg} |")
            if len(r.errors) > 50:
                lines.append(f"| ... | | *{len(r.errors) - 50} more errors not shown* |")
            lines.append("\n</details>")

    # -- Warnings (collapsible) ------------------------------------------------
    all_warnings = [(r.file.name, w) for r in results for w in r.warnings]
    if all_warnings:
        lines.append(f"\n<details>")
        lines.append(f"<summary>Warnings ({len(all_warnings)})</summary>\n")
        lines.append("| File | Line | Code | Message |")
        lines.append("|------|-----:|------|---------|")
        for fname, w in all_warnings[:50]:
            escaped_msg = w.message.replace('|', '\\|')
            fix_tag = " (auto-fixable)" if w.fixable else ""
            lines.append(f"| `{fname}` | {w.line} | `{w.code}` | {escaped_msg}{fix_tag} |")
        if len(all_warnings) > 50:
            lines.append(f"| | ... | | *{len(all_warnings) - 50} more not shown* |")
        lines.append("\n</details>")

    # -- Notices (collapsible) -------------------------------------------------
    all_notices = [(r.file.name, n) for r in results for n in r.notices]
    if all_notices:
        lines.append(f"\n<details>")
        lines.append(f"<summary>Notices ({len(all_notices)})</summary>\n")
        lines.append("| File | Line | Code | Message |")
        lines.append("|------|-----:|------|---------|")
        for fname, n in all_notices[:30]:
            escaped_msg = n.message.replace('|', '\\|')
            lines.append(f"| `{fname}` | {n.line} | `{n.code}` | {escaped_msg} |")
        if len(all_notices) > 30:
            lines.append(f"| | ... | | *{len(all_notices) - 30} more not shown* |")
        lines.append("\n</details>")

    # -- Footer ----------------------------------------------------------------
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    lines.append(f"\n---")
    lines.append(f"*Generated by `validate_blocklist.py` at {now}*")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate AdBlock-format blocklists and update metadata headers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "files",
        nargs='*',
        default=["blocklist.txt"],
        metavar="FILE",
        help="Blocklist file(s) to validate. Defaults to blocklist.txt.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate only; do not write any changes to disk.",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix safe issues (trailing whitespace, missing ^, tabs, duplicates).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat all warnings as errors.",
    )
    parser.add_argument(
        "--sort",
        action="store_true",
        help="Sort rules alphabetically (preserves header block).",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print detailed statistics (TLD distribution, etc.).",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip writing GitHub Actions step summary.",
    )
    args = parser.parse_args()

    # Resolve file list (support glob patterns passed as strings)
    file_paths: List[Path] = []
    for pattern in args.files:
        expanded = list(Path().glob(pattern))
        if expanded:
            file_paths.extend(expanded)
        else:
            file_paths.append(Path(pattern))

    results: List[ValidationResult] = []
    failed_files: List[Path] = []

    # -- Process each file -----------------------------------------------------
    workspace = os.environ.get("GITHUB_WORKSPACE", "")

    t_total_start = time.monotonic()

    for fp in file_paths:
        resolved = fp.resolve()
        try:
            rel = str(resolved.relative_to(workspace)) if workspace else str(fp)
        except ValueError:
            rel = str(fp)

        result = process_file(
            resolved,
            dry_run=args.dry_run,
            fix=args.fix,
            strict=args.strict,
            sort=args.sort,
            stats=args.stats,
            rel_path=rel,
        )
        results.append(result)
        if not result.is_valid():
            failed_files.append(resolved)

    total_elapsed = time.monotonic() - t_total_start

    # -- Step summary ----------------------------------------------------------
    if not args.no_summary:
        summary = build_step_summary(results, failed_files, elapsed=total_elapsed)
        write_step_summary(summary)

    # -- Final status ----------------------------------------------------------
    total_rules = sum(r.total_rules for r in results)
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)
    total_notices = sum(len(r.notices) for r in results)
    total_fixed = sum(r.fixed_count for r in results)
    passed = len(failed_files) == 0

    # -- Set GITHUB_OUTPUT variables for downstream steps ----------------------
    gha_set_output("validation_passed", str(passed).lower())
    gha_set_output("total_rules", total_rules)
    gha_set_output("total_errors", total_errors)
    gha_set_output("total_warnings", total_warnings)
    gha_set_output("total_notices", total_notices)
    gha_set_output("total_fixed", total_fixed)
    gha_set_output("files_processed", len(results))
    gha_set_output("files_failed", len(failed_files))
    gha_set_output("elapsed_seconds", f"{total_elapsed:.2f}")

    # JSON blob for advanced downstream consumption
    summary_json = json.dumps({
        "passed": passed,
        "files": len(results),
        "failed_files": [str(f.name) for f in failed_files],
        "total_rules": total_rules,
        "errors": total_errors,
        "warnings": total_warnings,
        "notices": total_notices,
        "fixed": total_fixed,
        "elapsed": round(total_elapsed, 2),
        "rule_counts": dict(
            sum((Counter(r.rule_counts) for r in results), Counter())
        ),
    }, separators=(',', ':'))
    gha_set_output("summary_json", summary_json)

    # -- Set GITHUB_ENV for use in subsequent steps ----------------------------
    gha_set_env("BLOCKLIST_RULES", str(total_rules))
    gha_set_env("BLOCKLIST_VALID", str(passed).lower())

    # -- Console output --------------------------------------------------------
    print()
    print("-" * 60)
    if failed_files:
        print(_c(
            f"FAILED -- {len(failed_files)}/{len(results)} file(s) have errors.",
            Color.RED, Color.BOLD,
        ))
        print(f"  Total errors:   {total_errors}")
        print(f"  Total warnings: {total_warnings}")
        print(f"  Elapsed:        {total_elapsed:.2f}s")
        sys.exit(1)
    else:
        print(_c(
            f"ALL PASSED -- {len(results)} file(s), {total_rules} total rules.",
            Color.GREEN, Color.BOLD,
        ))
        if total_warnings:
            print(f"  Total warnings: {total_warnings}")
        if total_fixed:
            print(f"  Auto-fixed:     {total_fixed} line(s)")
        print(f"  Elapsed:        {total_elapsed:.2f}s")
        sys.exit(0)


if __name__ == "__main__":
    main()

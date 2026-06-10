"""
hapara.fail AdBlock Plus Blocklist Validator & Metadata Updater
================================================================
Validates AdBlock Plus format blocklists, emits GitHub Actions annotations,
writes a step summary, and atomically updates file metadata on success.

Usage:
  python scripts/process_blocklist.py [file ...]
  python scripts/process_blocklist.py blocklist.txt --dry-run
  python scripts/process_blocklist.py *.txt --fix       # auto-fix safe issues
  python scripts/process_blocklist.py --strict          # warnings become errors
  python scripts/process_blocklist.py --sort            # sort rules alphabetically
  python scripts/process_blocklist.py --stats           # print detailed statistics
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

# Valid AdBlock option modifiers after `$`. Store canonical keys without a
# leading "~"; inverse options are normalized while validating.
VALID_OPTIONS: Set[str] = {
    "script", "image", "stylesheet", "object", "xmlhttprequest", "object-subrequest",
    "subdocument", "document", "elemhide", "generichide", "genericblock", "other",
    "third-party", "first-party", "all", "popup", "media", "font", "websocket",
    "webrtc", "ping", "csp", "rewrite", "important", "badfilter", "redirect",
    "redirect-rule", "denyallow",
    "domain", "app", "network", "permissions", "stealth", "cookie",
    "removeparam", "removeheader", "header", "method", "to", "from",
    "match-case", "replace", "urltransform",
    # common shorthand
    "3p", "1p", "xhr",
}

# Known TLDs for domain validation (subset of common ones)
_KNOWN_TLDS: Set[str] = {
    "com", "net", "org", "io", "co", "us", "uk", "de", "fr", "jp", "ru",
    "cn", "br", "in", "au", "ca", "it", "es", "nl", "se", "no", "fi",
    "info", "biz", "me", "tv", "cc", "xyz", "online", "site", "app",
    "dev", "tech", "cloud", "ai", "gg", "ly", "to", "sh", "fm", "gg",
    "edu", "gov", "mil", "int",
}

# Regex to identify metadata/comment lines
_COMMENT        = re.compile(r'^!')
_ADBLOCK_HDR    = re.compile(r'^\[Adblock', re.IGNORECASE)

# Header metadata patterns
HEADER_PATTERNS: Dict[str, Pattern] = {
    'count':    re.compile(r'^! Number of entries:.*',  re.IGNORECASE),
    'modified': re.compile(r'^! Last modified:.*',      re.IGNORECASE),
    'version':  re.compile(r'^! Version:.*',            re.IGNORECASE),
}

# Pattern for detecting IP address rules (hosts-file format mixed in)
_IP_RULE = re.compile(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+\S+')

# Pattern for DNS-compatible hostname rules
_DNS_HOSTNAME_RE = re.compile(
    r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
    r'(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})$'
)

_CONTENT_MARKERS: Tuple[Tuple[str, str, bool], ...] = (
    ("#@$#", "scriptlet-allow", True),
    ("#$#", "scriptlet", False),
    ("#@#", "cosmetic-allow", True),
    ("#?#", "extended-css", False),
    ("##", "cosmetic", False),
    ("$$", "html-filter", False),
)

_OPTION_ALIASES = {
    "3p": "third-party",
    "1p": "first-party",
    "xhr": "xmlhttprequest",
}


@dataclass(frozen=True)
class ParsedRule:
    raw: str
    category: str
    is_exception: bool = False
    pattern: str = ""
    options: Tuple[str, ...] = ()
    dns_compatible: bool = False
    marker: str = ""
    domain: Optional[str] = None
    is_regex: bool = False


def _is_hash_comment(line: str) -> bool:
    """Treat legacy # comments as comments unless they are ABP content rules."""
    if not line.startswith('#'):
        return False
    return not any(marker in line for marker, _, _ in _CONTENT_MARKERS)


def _split_options(rule_body: str) -> Tuple[str, Tuple[str, ...], bool]:
    """Split a network rule into pattern/options and identify ABP regex rules."""
    if rule_body.startswith('/'):
        escaped = False
        closing_idx = -1
        for idx in range(1, len(rule_body)):
            ch = rule_body[idx]
            if ch == '\\' and not escaped:
                escaped = True
                continue
            if ch == '/' and not escaped:
                closing_idx = idx
            escaped = False

        if closing_idx > 0:
            if closing_idx == len(rule_body) - 1:
                return rule_body, (), True
            if rule_body[closing_idx + 1] == '$':
                options = tuple(
                    opt.strip()
                    for opt in rule_body[closing_idx + 2:].split(',')
                    if opt.strip()
                )
                return rule_body[:closing_idx + 1], options, True

    dollar_idx = rule_body.rfind('$')
    if dollar_idx > 0:
        options = tuple(
            opt.strip()
            for opt in rule_body[dollar_idx + 1:].split(',')
            if opt.strip()
        )
        return rule_body[:dollar_idx], options, False

    return rule_body, (), False


def _extract_dns_domain(pattern: str) -> Optional[str]:
    """Return hostname when pattern is the DNS-safe ABP domain-anchor shape."""
    if not (pattern.startswith('||') and pattern.endswith('^')):
        return None
    domain = pattern[2:-1]
    if not domain:
        return None
    if any(ch in domain for ch in ('/', '*', ':', '|', '^')) or any(ch.isspace() for ch in domain):
        return None
    if not _DNS_HOSTNAME_RE.match(domain):
        return None
    return domain.lower()


def _extract_domain_anchor_body(pattern: str) -> Optional[str]:
    """Return the body of a ||domain^ style pattern, even if malformed."""
    if not (pattern.startswith('||') and pattern.endswith('^')):
        return None
    return pattern[2:-1].lower()


def parse_rule(line: str) -> Optional[ParsedRule]:
    """
    Parse enough ABP syntax to distinguish valid browser-level rules from the
    narrower DNS-compatible subset this repository publishes.
    """
    if not line:
        return None
    if _COMMENT.match(line) or _ADBLOCK_HDR.match(line) or _is_hash_comment(line):
        return None

    for marker, category, is_exception in _CONTENT_MARKERS:
        if marker in line:
            selector = line.split(marker, 1)[1]
            return ParsedRule(
                raw=line,
                category=category,
                is_exception=is_exception,
                pattern=selector,
                marker=marker,
                dns_compatible=False,
            )

    is_exception = line.startswith('@@')
    body = line[2:] if is_exception else line
    pattern, options, is_regex = _split_options(body)
    domain = _extract_dns_domain(pattern)
    dns_compatible = domain is not None and not options and not is_regex

    if is_exception:
        category = "allow"
    elif is_regex:
        category = "regex"
    else:
        category = "block"

    return ParsedRule(
        raw=line,
        category=category,
        is_exception=is_exception,
        pattern=pattern,
        options=options,
        dns_compatible=dns_compatible,
        domain=domain,
        is_regex=is_regex,
    )


def classify_rule(line: str) -> Optional[str]:
    """Return a human-readable category string, or None if not a rule."""
    parsed = parse_rule(line)
    return parsed.category if parsed else None


def is_rule(line: str) -> bool:
    return parse_rule(line) is not None


def extract_domain(rule: str) -> Optional[str]:
    """Extract the domain from a network block/allow rule like ||domain.com^."""
    parsed = parse_rule(rule)
    return parsed.domain if parsed else None


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
        if _COMMENT.match(stripped) or _ADBLOCK_HDR.match(stripped) or _is_hash_comment(stripped):
            self.result.comment_lines += 1

        # Check: Hosts-file format mixed in (0.0.0.0 or 127.0.0.1)
        if _IP_RULE.match(stripped):
            self._diag("error", line_num,
                       f"Hosts-file format detected: '{stripped}'. Convert to AdBlock syntax (||domain^).",
                       code="E003")
            return

        parsed = parse_rule(stripped)

        # Skip non-rules for rule-specific checks
        if parsed is None:
            return

        self._first_rule_seen = True
        category = parsed.category

        # -- Rule-specific checks ----------------------------------------------

        # Check: Trailing whitespace on a rule
        if line != line.rstrip():
            self._diag("warning", line_num,
                       "Rule has trailing whitespace.",
                       fixable=True, code="W003")

        # Check: Spaces inside a non-regex network pattern. ABP options such as
        # csp= may contain spaces, so validate the parsed pattern only.
        if category in ("block", "allow", "regex") and not parsed.is_regex and ' ' in parsed.pattern:
            self._diag("error", line_num,
                       f"Network rule pattern contains illegal spaces: '{parsed.pattern}'",
                       code="E005")

        # Check: Empty / stub rules
        if stripped in (
            '||', '@@', '@@||', '||^', '@@^', '@@||^',
            '##', '#@#', '#?#', '#$#', '#@$#', '$$', '##.', '#@#.',
        ):
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
        if parsed.options:
            self._validate_options(parsed, line_num)

        # Check: Duplicate detection (normalised to lowercase for domains)
        normalised = stripped.lower() if category in ("block", "allow") else stripped
        if normalised in self._seen_rules:
            self._diag("error", line_num,
                       f"Duplicate rule: '{stripped}'",
                       fixable=True, code="E008")
        else:
            self._seen_rules.add(normalised)
            self.result.rule_counts[category] = \
                self.result.rule_counts.get(category, 0) + 1

        # Check: Missing separator ^ on domain rules (warning)
        missing_simple_separator = (
            category == "block"
            and stripped.startswith('||')
            and '$' not in stripped
            and not stripped.endswith('^')
            and '/' not in stripped[2:]
            and '*' not in stripped[2:]
        )
        if missing_simple_separator:
            self._diag("warning", line_num,
                       f"Network rule missing '^' separator at end: '{stripped}'",
                       fixable=True, code="W004")

        # Check: Redundancy -- ||sub.domain^ when ||domain^ already exists
        if category == "block" and parsed.dns_compatible and parsed.domain:
            domain = parsed.domain
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
        if category in ("cosmetic", "cosmetic-allow", "extended-css", "scriptlet", "scriptlet-allow", "html-filter"):
            if not parsed.pattern.strip():
                self._diag("error", line_num,
                           f"Content rule has empty body after '{parsed.marker}'.",
                           code="E009")

        # Check: Domain with consecutive dots (e.g. ||example..com^)
        if category in ("block", "allow"):
            anchor_body = _extract_domain_anchor_body(parsed.pattern)
            if anchor_body:
                if '..' in anchor_body:
                    self._diag("error", line_num,
                               f"Domain contains consecutive dots: '{anchor_body}'",
                               code="E010")
                if anchor_body.endswith('.'):
                    self._diag("warning", line_num,
                               f"Domain has trailing dot: '{anchor_body}'",
                               code="W005")

            if parsed.domain:
                domain = parsed.domain
                # Track TLD distribution
                tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
                if tld:
                    self.result.tld_distribution[tld] = \
                        self.result.tld_distribution.get(tld, 0) + 1
                self.result.domain_list.append(domain)
            elif anchor_body:
                if not any(ch in anchor_body for ch in ('/', '*', ':', '|', '^')) and not any(ch.isspace() for ch in anchor_body):
                    self._diag("error", line_num,
                               f"Invalid DNS hostname in domain-anchor rule: '{anchor_body}'",
                               code="E016")
        # Check: Regex rule validation
        if parsed.is_regex:
            inner = parsed.pattern[1:-1]
            try:
                re.compile(inner)
            except re.error as exc:
                self._diag("error", line_num,
                           f"Invalid regex pattern: {exc}",
                           code="E011")

        # Check: DNS compatibility. Broader ABP syntax is parsed, but this
        # repository publishes a DNS-focused list.
        if not parsed.dns_compatible and not missing_simple_separator:
            if category in ("cosmetic", "cosmetic-allow", "extended-css", "scriptlet", "scriptlet-allow", "html-filter"):
                self._diag("error", line_num,
                           f"DNS-incompatible ABP content rule '{stripped}'. "
                           "Content, style, snippet, and HTML filters require browser-level filtering.",
                           code="E014")
            else:
                self._diag("error", line_num,
                           f"DNS-incompatible network rule '{stripped}'. "
                           "DNS blocklists can only enforce '||hostname^' and '@@||hostname^' rules without options.",
                           code="E015")

    def _validate_options(self, parsed: ParsedRule, line_num: int) -> None:
        """Validate the $option,list part of a network rule."""
        raw_options = parsed.options

        for opt in raw_options:
            key = self._option_key(opt)
            if key and key not in VALID_OPTIONS:
                self._diag("warning", line_num,
                           f"Unknown or non-standard option '${opt}'. "
                           "Verify it's supported by your target adblocker.",
                           code="W006")

        # Check for conflicting options
        positive = {self._option_key(o) for o in raw_options if not o.startswith('~')}
        negative = {self._option_key(o) for o in raw_options if o.startswith('~')}
        for key in sorted(positive & negative):
            self._diag("error", line_num,
                       f"Conflicting options: '{key}' and '~{key}' on same rule.",
                       code="E012")

    @staticmethod
    def _option_key(option: str) -> str:
        raw_key = option[1:] if option.startswith('~') else option
        key = raw_key.split('=', 1)[0].lower()
        return _OPTION_ALIASES.get(key, key)


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
        if in_header and (
            not stripped
            or _COMMENT.match(stripped)
            or _ADBLOCK_HDR.match(stripped)
            or _is_hash_comment(stripped)
        ):
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
        "scriptlet-allow": "Scriptlet allow",
        "html-filter": "HTML filter",
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

    # -- Revalidate after mutating passes --------------------------------------
    if fix or sort:
        fixed_count = result.fixed_count
        post_validator = BlocklistValidator(strict=strict)
        post_validator.reset(file_path)
        for i, line in enumerate(working_lines, 1):
            post_validator.validate_line(line, i)
        result = post_validator.result
        result.fixed_count = fixed_count

        if result.errors:
            print(_c(f"\n  Remaining errors after fixes ({len(result.errors)}):", Color.RED, Color.BOLD))
            for e in result.errors:
                tag = f" [{e.code}]" if e.code else ""
                print(f"    line {e.line:>5}: {e.message}{tag}")
            print(_c(
                f"\n  [FAIL] Validation FAILED -- {len(result.errors)} error(s) remain after fixes.",
                Color.RED, Color.BOLD,
            ))
            return result

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
        "scriptlet-allow": "Scriptlet allow",
        "html-filter": "HTML filter",
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
    lines.append(f"*Generated by `scripts/process_blocklist.py` at {now}*")

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

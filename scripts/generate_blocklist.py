"""Validate the canonical hapara.fail data and generate every distribution format."""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable
from urllib.parse import urlparse

import idna


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "data" / "blocklist.csv"
DEFAULT_OUTPUT_DIR = ROOT / "dist"
LEGACY_ADBLOCK_PATH = ROOT / "blocklist.txt"

FIELDS = ("action", "domain", "service", "category", "description", "source", "added")
CATEGORIES = {"monitoring", "filtering", "device-management", "parental-control", "other"}
ACTIONS = {"block", "allow"}
ASCII_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

PROJECT = {
    "name": "hapara.fail Blocklist",
    "homepage": "https://www.hapara.fail/",
    "repository": "https://github.com/hapara-fail/blocklist",
    "license": "GPL-3.0-only",
    "license_url": "https://github.com/hapara-fail/blocklist/blob/main/LICENSE",
    "description": (
        "Blocks school-mandated surveillance software, spyware, and other invasive "
        "educational technology services."
    ),
}


class ValidationError(ValueError):
    """Raised when canonical input is invalid."""


@dataclass(frozen=True)
class Entry:
    action: str
    domain: str
    unicode_domain: str
    service: str
    category: str
    description: str
    source: str
    added: str


def _fail(line: int, message: str) -> ValidationError:
    return ValidationError(f"line {line}: {message}")


def normalize_domain(value: str, line: int = 0) -> tuple[str, str]:
    """Return canonical IDNA ASCII and Unicode forms for a DNS hostname."""
    if not value or value != value.strip():
        raise _fail(line, "domain is empty or has surrounding whitespace")
    if value.endswith("."):
        raise _fail(line, "domain must not have a trailing root dot")
    if "://" in value or any(char in value for char in "/*^|@:#"):
        raise _fail(line, "domain must be a hostname, not a URL, wildcard, or filter rule")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise _fail(line, "IP addresses are not domain entries")

    try:
        ascii_domain = idna.encode(
            value,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii").lower()
        unicode_domain = idna.decode(ascii_domain).lower()
    except idna.IDNAError as exc:
        raise _fail(line, f"invalid IDN/domain: {exc}") from exc

    if len(ascii_domain) > 253 or not ASCII_DOMAIN_RE.fullmatch(ascii_domain):
        raise _fail(line, "domain must contain at least two valid DNS labels")
    return ascii_domain, unicode_domain


def _clean_text(value: str | None, field: str, line: int, *, required: bool = False) -> str:
    value = "" if value is None else value
    if value != value.strip():
        raise _fail(line, f"{field} has surrounding whitespace")
    if any(ord(char) < 32 for char in value):
        raise _fail(line, f"{field} contains a control character")
    if required and not value:
        raise _fail(line, f"{field} is required")
    return value


def load_entries(path: Path = DEFAULT_SOURCE) -> list[Entry]:
    """Parse and validate the canonical CSV file."""
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ValidationError(f"cannot read {path}: {exc}") from exc

    entries: list[Entry] = []
    seen: dict[str, int] = {}
    with handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValidationError(
                "header must be exactly: " + ",".join(FIELDS)
            )
        for row in reader:
            line = reader.line_num
            action_raw = (row.get("action") or "").strip()
            if not action_raw and all(not (value or "").strip() for value in row.values()):
                continue
            if action_raw.startswith("#"):
                continue
            if None in row:
                raise _fail(line, "row has more fields than the header")

            action = _clean_text(row["action"], "action", line, required=True).lower()
            if action not in ACTIONS:
                raise _fail(line, f"action must be one of: {', '.join(sorted(ACTIONS))}")
            domain, unicode_domain = normalize_domain(row["domain"] or "", line)
            service = _clean_text(row["service"], "service", line, required=True)
            category = _clean_text(row["category"], "category", line, required=True).lower()
            description = _clean_text(row["description"], "description", line)
            source = _clean_text(row["source"], "source", line)
            added = _clean_text(row["added"], "added", line)

            if category not in CATEGORIES:
                raise _fail(line, f"category must be one of: {', '.join(sorted(CATEGORIES))}")
            if len(service) > 120 or len(description) > 500:
                raise _fail(line, "service or description is too long")
            if source:
                parsed = urlparse(source)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise _fail(line, "source must be an absolute HTTP(S) URL")
            if added:
                try:
                    date.fromisoformat(added)
                except ValueError as exc:
                    raise _fail(line, "added must use YYYY-MM-DD") from exc
            if domain in seen:
                raise _fail(line, f"duplicate domain; first declared on line {seen[domain]}")
            seen[domain] = line
            entries.append(
                Entry(action, domain, unicode_domain, service, category, description, source, added)
            )

    if not entries:
        raise ValidationError("canonical source contains no entries")
    return sorted(entries, key=lambda item: (item.domain, item.action))


def generation_time(explicit: str | None = None) -> datetime:
    if explicit:
        try:
            value = datetime.fromisoformat(explicit.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("--timestamp must be ISO 8601") from exc
        if value.tzinfo is None:
            raise ValidationError("--timestamp must include a timezone")
        return value.astimezone(timezone.utc).replace(microsecond=0)
    if epoch := os.environ.get("SOURCE_DATE_EPOCH"):
        try:
            return datetime.fromtimestamp(int(epoch), timezone.utc).replace(microsecond=0)
        except (ValueError, OverflowError) as exc:
            raise ValidationError("SOURCE_DATE_EPOCH must be a valid Unix timestamp") from exc
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _comment_header(prefix: str, generated: datetime, format_name: str, count: int) -> list[str]:
    version = generated.strftime("%Y%m%d%H%M")
    return [
        f"{prefix} {PROJECT['name']}",
        f"{prefix} {PROJECT['description']}",
        f"{prefix} Homepage: {PROJECT['homepage']}",
        f"{prefix} Repository: {PROJECT['repository']}",
        f"{prefix} License: {PROJECT['license']} ({PROJECT['license_url']})",
        f"{prefix} Generated: {_timestamp(generated)}",
        f"{prefix} Version: {version}",
        f"{prefix} Update interval: 3 days",
        f"{prefix} Format: {format_name}",
        f"{prefix} Blocking entries: {count}",
        f"{prefix} Generated file; edit data/blocklist.csv instead.",
    ]


def render_outputs(entries: Iterable[Entry], generated: datetime) -> dict[str, str]:
    entries = sorted(entries, key=lambda item: (item.domain, item.action))
    blocked = [entry for entry in entries if entry.action == "block"]
    version = generated.strftime("%Y%m%d%H%M")

    adblock = [
        "[Adblock Plus 2.0]",
        f"! Title: {PROJECT['name']}",
        f"! Description: {PROJECT['description']}",
        f"! Homepage: {PROJECT['homepage']}",
        f"! License: {PROJECT['license_url']}",
        "! Expires: 3 days",
        f"! Version: {version}",
        f"! Last modified: {_timestamp(generated)}",
        "! Format: Adblock Plus / AdGuard / uBlock Origin",
        f"! Number of entries: {len(entries)}",
        "! Generated file; edit data/blocklist.csv instead.",
        "",
    ]
    adblock.extend(
        ("@@" if entry.action == "allow" else "") + f"||{entry.domain}^"
        for entry in entries
    )

    domains = [entry.domain for entry in blocked]

    hosts = _comment_header("#", generated, "hosts(5), 0.0.0.0 sink", len(blocked))
    hosts.append("")
    hosts.extend(f"0.0.0.0 {entry.domain}" for entry in blocked)

    dnsmasq = _comment_header("#", generated, "dnsmasq NXDOMAIN address rules", len(blocked))
    dnsmasq.append("")
    dnsmasq.extend(f"address=/{entry.domain}/" for entry in blocked)

    unbound = _comment_header("#", generated, "Unbound always_nxdomain local zones", len(blocked))
    unbound.extend(["", "server:"])
    unbound.extend(f'    local-zone: "{entry.domain}." always_nxdomain' for entry in blocked)

    serial = int(generated.timestamp())
    if not 0 <= serial <= 4_294_967_295:
        raise ValidationError("generated timestamp cannot be represented as a 32-bit SOA serial")
    rpz = _comment_header(";", generated, "DNS Response Policy Zone (NXDOMAIN)", len(blocked))
    rpz.extend(
        [
            "",
            "$ORIGIN rpz.hapara.fail.",
            "$TTL 1h",
            "@ IN SOA localhost. hostmaster.hapara.fail. (",
            f"    {serial} ; serial (Unix timestamp)",
            "    1h         ; refresh",
            "    15m        ; retry",
            "    30d        ; expire",
            "    1h         ; negative cache TTL",
            ")",
            "  IN NS localhost.",
            "",
        ]
    )
    for entry in blocked:
        rpz.extend((f"{entry.domain} CNAME .", f"*.{entry.domain} CNAME ."))

    json_entries = [asdict(entry) for entry in entries]
    payload = {
        "schema_version": "1.0.0",
        "list_version": version,
        "generated_at": _timestamp(generated),
        "update_interval_hours": 72,
        "project": PROJECT,
        "entry_count": len(entries),
        "block_entry_count": len(blocked),
        "allow_entry_count": len(entries) - len(blocked),
        "entries": json_entries,
    }

    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=Entry.__dataclass_fields__.keys(), lineterminator="\n")
    writer.writeheader()
    writer.writerows(json_entries)

    def lines(values: list[str]) -> str:
        return "\n".join(values) + "\n"

    return {
        "adblock.txt": lines(adblock),
        "domains.txt": lines(domains),
        "hosts.txt": lines(hosts),
        "dnsmasq.conf": lines(dnsmasq),
        "unbound.conf": lines(unbound),
        "blocklist.rpz": lines(rpz),
        "blocklist.json": json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        "blocklist.csv": csv_buffer.getvalue(),
    }


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as temp:
        temp.write(content)
        temp_path = Path(temp.name)
    temp_path.replace(path)


def write_outputs(outputs: dict[str, str], output_dir: Path, legacy_path: Path | None) -> None:
    for name, content in outputs.items():
        _write_atomic(output_dir / name, content)
    if legacy_path is not None:
        _write_atomic(legacy_path, outputs["adblock.txt"])


def check_outputs(outputs: dict[str, str], output_dir: Path, legacy_path: Path | None) -> list[Path]:
    stale: list[Path] = []
    expected = {output_dir / name: content for name, content in outputs.items()}
    if legacy_path is not None:
        expected[legacy_path] = outputs["adblock.txt"]
    for path, content in expected.items():
        try:
            actual = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            stale.append(path)
        else:
            if actual != content:
                stale.append(path)
    return stale


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timestamp", help="ISO 8601 build timestamp (or use SOURCE_DATE_EPOCH)")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--check", action="store_true", help="fail if committed outputs differ")
    parser.add_argument("--no-legacy", action="store_true", help="do not update root blocklist.txt")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        entries = load_entries(args.source)
        if args.validate_only:
            print(f"Validated {len(entries)} canonical entries in {args.source}")
            return 0
        generated = generation_time(args.timestamp)
        outputs = render_outputs(entries, generated)
        legacy = None if args.no_legacy else LEGACY_ADBLOCK_PATH
        if args.check:
            stale = check_outputs(outputs, args.output_dir, legacy)
            if stale:
                print("Generated files are stale:", file=sys.stderr)
                for path in stale:
                    print(f"  {path}", file=sys.stderr)
                return 1
            suffix = " and the legacy Adblock path" if legacy is not None else ""
            print(f"Verified {len(outputs)} generated formats{suffix}")
            return 0
        write_outputs(outputs, args.output_dir, legacy)
        print(
            f"Generated {len(outputs)} formats from {len(entries)} entries "
            f"({sum(entry.action == 'block' for entry in entries)} blocking)"
        )
        return 0
    except (ValidationError, csv.Error, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

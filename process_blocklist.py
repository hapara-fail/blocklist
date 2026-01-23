import argparse
import re
import sys
import shutil
from pathlib import Path
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile
from typing import List, Set, Pattern, Dict, Tuple

class Color:
    """ANSI Escape codes for colored terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

HEADER_PATTERNS: Dict[str, Pattern] = {
    'count': re.compile(r'^! Number of entries:.*', re.IGNORECASE),
    'modified': re.compile(r'^! Last modified:.*', re.IGNORECASE),
    'version': re.compile(r'^! Version:.*', re.IGNORECASE),
}

def is_rule(line: str) -> bool:
    """
    Determines if a line is a countable rule.
    Ignores comments (!), empty lines, and the [Adblock] header.
    """
    if not line or line.startswith('!') or line.startswith('[Adblock'):
        return False
    return line.startswith('||') or line.startswith('@@')

class BlocklistValidator:
    """
    Handles the logic for checking rules and maintaining the count.
    """
    def __init__(self):
        self.seen_rules: Set[str] = set()
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.count = 0

    def validate_line(self, line: str, line_num: int):
        """
        Runs comprehensive checks on a single line.
        """
        stripped = line.strip()

        # --- Check 1: Invisible Characters ---
        # Tabs break many parsers; use spaces instead.
        if '\t' in line:
            self.errors.append(f"Line {line_num}: Contains tab character (\\t). Use spaces.")

        # If it's not a rule (comment or empty), we stop validation here.
        if not is_rule(stripped):
            return

        # --- Check 2: Invalid Spaces ---
        # Blocking rules (e.g., ||example.com) must not contain spaces.
        if ' ' in stripped:
            self.errors.append(f"Line {line_num}: Rule contains illegal spaces: '{stripped}'")

        # --- Check 3: Empty or Malformed Rules ---
        # Checks for incomplete anchors like just "||" or "@@"
        if stripped in ['||', '@@', '||^', '@@^']:
            self.errors.append(f"Line {line_num}: Rule is empty/incomplete.")

        # --- Check 4: Protocol violations (NEW LOGIC) ---
        # Adblock rules usually shouldn't contain http:// or https://
        if '://' in stripped:
            self.errors.append(f"Line {line_num}: Rule contains protocol (http/https). Remove '://'.")

        # --- Check 5: Duplicate Detection ---
        if stripped in self.seen_rules:
            self.errors.append(f"Line {line_num}: Duplicate rule found: '{stripped}'")
        else:
            self.seen_rules.add(stripped)
            self.count += 1

        # --- Check 6: Style Consistency (Warnings only) ---
        # It is best practice to end domain blocks with the separator char ^
        if stripped.startswith('||') and not stripped.endswith('^'):
            self.warnings.append(f"Line {line_num}: Rule missing separator '^' at end: '{stripped}'")

    def is_valid(self) -> bool:
        """Returns True only if there are 0 errors."""
        return len(self.errors) == 0

def get_timestamps() -> Tuple[str, str]:
    """Generates the current UTC timestamps for the headers."""
    now_utc = datetime.now(timezone.utc)
    # Format: 07 Jan 2026 00:55 UTC
    ts_str = now_utc.strftime('%d %b %Y %H:%M UTC')
    # Format: 2026.0107.0055
    ver_str = now_utc.strftime('%Y.%m%d.%H%M')
    return ts_str, ver_str

def process_blocklist(file_path: Path, dry_run: bool = False):
    """
    Main execution logic: Read -> Validate -> Write (if valid).
    """
    if not file_path.exists():
        print(f"{Color.FAIL}Critical: File '{file_path}' not found.{Color.ENDC}")
        sys.exit(1)

    print(f"{Color.HEADER}Processing blocklist: {file_path.name}{Color.ENDC}")
    
    validator = BlocklistValidator()
    
    # --- Pass 1: Read, Validate, and Count ---
    try:
        with file_path.open('r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                validator.validate_line(line, i)
    except UnicodeDecodeError:
        print(f"{Color.FAIL}Critical: File is not valid UTF-8.{Color.ENDC}")
        sys.exit(1)

    # --- Reporting Results ---
    
    # Print Warnings (Non-fatal issues)
    if validator.warnings:
        print(f"\n{Color.WARNING}Warnings (Style/Best Practices):{Color.ENDC}")
        for w in validator.warnings:
            print(f"  - {w}")

    # Print Errors (Fatal issues)
    if not validator.is_valid():
        print(f"\n{Color.FAIL}VALIDATION FAILED! Found {len(validator.errors)} errors:{Color.ENDC}")
        for e in validator.errors:
            print(f"  - {e}")
        print(f"\n{Color.FAIL}Fix these errors in '{file_path.name}' and run again.{Color.ENDC}")
        sys.exit(1) # Exit with code 1 to stop GitHub Actions

    # --- Success State ---
    ts_str, ver_str = get_timestamps()
    
    print(f"\n{Color.OKGREEN}Validation Passed!{Color.ENDC}")
    print(f"  - Valid Entries: {validator.count}")
    print(f"  - New Version:   {ver_str}")

    if dry_run:
        print(f"{Color.OKBLUE}Dry Run: Skipping file write.{Color.ENDC}")
        return

    # --- Pass 2: Atomic Write ---
    temp_dir = file_path.parent
    updates_made = 0

    try:
        with NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, dir=temp_dir) as temp_file:
            temp_path = Path(temp_file.name)
            
            with file_path.open('r', encoding='utf-8') as original_file:
                for line in original_file:
                    # Check if line matches any header we need to update
                    new_line = line
                    
                    if HEADER_PATTERNS['count'].match(line):
                        new_line = f"! Number of entries: {validator.count}\n"
                        updates_made += 1
                    elif HEADER_PATTERNS['modified'].match(line):
                        new_line = f"! Last modified: {ts_str}\n"
                        updates_made += 1
                    elif HEADER_PATTERNS['version'].match(line):
                        new_line = f"! Version: {ver_str}\n"
                        updates_made += 1
                    
                    temp_file.write(new_line)

        # Move temp file to original location
        if updates_made > 0:
            shutil.move(str(temp_path), str(file_path))
            print(f"{Color.OKGREEN}Success: File updated successfully.{Color.ENDC}")
        else:
            print(f"{Color.WARNING}Warning: Validated content, but found no metadata headers to update.{Color.ENDC}")
            temp_path.unlink() # Delete temp file since we didn't use it

    except Exception as e:
        print(f"{Color.FAIL}Critical Write Error: {e}{Color.ENDC}")
        # Clean up the temp file if it exists
        if 'temp_path' in locals() and temp_path.exists():
            temp_path.unlink()
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Validate and update AdBlock metadata.")
    parser.add_argument("filename", nargs='?', default="blocklist.txt", help="Path to blocklist file")
    parser.add_argument("--dry-run", action="store_true", help="Validate only, do not write changes")
    args = parser.parse_args()

    process_blocklist(Path(args.filename).resolve(), args.dry_run)

if __name__ == "__main__":
    main()
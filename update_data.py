import sys
import os
import re
from datetime import datetime, timezone

filename = 'blocklist.txt'
if len(sys.argv) >= 2:
    filename = sys.argv[1]

print(f"Targeting file: {filename}")

if not os.path.exists(filename):
    print(f"Error: The file '{filename}' was not found in the current directory.")
    print("Usage: python count_entries.py [filename]")
    sys.exit()

count = 0
lines = []

entry_count_pattern = re.compile(r'^! Number of entries:.*')
last_modified_pattern = re.compile(r'^! Last modified:.*')
version_pattern = re.compile(r'^! Version:.*')

now_utc = datetime.now(timezone.utc)

timestamp_str = now_utc.strftime('%d %b %Y %H:%M UTC')

version_str = now_utc.strftime('%Y.%m%d.%H%M')

try:
    with open(filename, 'r', encoding='utf-8') as f:
        file_content = f.readlines()

    for line in file_content:
        stripped = line.strip()
        if stripped.startswith('||') or stripped.startswith('@@'):
            count += 1
        lines.append(line)

    print(f"Calculated entries: {count}")
    print(f"New timestamp:      {timestamp_str}")
    print(f"New version:        {version_str}")

    with open(filename, 'w', encoding='utf-8') as f:
        updates_made = 0
        for line in lines:
            if entry_count_pattern.match(line):
                f.write(f"! Number of entries: {count}\n")
                updates_made += 1
            elif last_modified_pattern.match(line):
                f.write(f"! Last modified: {timestamp_str}\n")
                updates_made += 1
            elif version_pattern.match(line):
                f.write(f"! Version: {version_str}\n")
                updates_made += 1
            else:
                f.write(line)

    if updates_made > 0:
        print(f"Success: Updated '{filename}' with new stats.")
    else:
        print("Warning: Counted entries but found no metadata lines to update.")

except Exception as e:
    print(f"An error occurred: {e}")
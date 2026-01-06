import sys
import os

if len(sys.argv) < 2:
    print("Error: No filename provided.")
    print("Usage: python count_entries.py blocklist.txt")
    sys.exit()

filename = sys.argv[1]
print(f"Reading file: {filename}")

if not os.path.exists(filename):
    print(f"Error: The file '{filename}' was not found in this folder.")
    sys.exit()

count = 0
try:
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            # Check if line starts with ||
            if line.strip().startswith('||'):
                count += 1

    print(f"Number of entries: {count}")

except Exception as e:
    print(f"An error occurred: {e}")
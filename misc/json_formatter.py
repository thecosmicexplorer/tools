#!/usr/bin/env python3
"""JSON Formatter & Validator
Generated: 2026-03-09
Usage: python json_formatter.py [file.json]   or pipe JSON via stdin
"""
import json, sys

def fmt(data):
    try:
        parsed = json.loads(data)
        print(json.dumps(parsed, indent=2, sort_keys=True))
        print("\n✓ Valid JSON", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

fmt(open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read())

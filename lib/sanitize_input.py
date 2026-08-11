#!/usr/bin/env python3
"""
Sanitize Input CLI

Usage:
    python3 sanitize_input.py "user input here"
    echo "user input" | python3 sanitize_input.py -
"""

import sys
import json
try:
    from lib.defense_core import PromptInjectionDetector
except ModuleNotFoundError:  # Support the documented `python3 lib/...` form.
    from defense_core import PromptInjectionDetector


def main():
    redact_only = "--redact" in sys.argv[1:]
    args = [arg for arg in sys.argv[1:] if arg != "--redact"]

    if len(args) < 1:
        print("Usage: python3 sanitize_input.py [--redact] <input>")
        print("   or: echo <input> | python3 sanitize_input.py [--redact] -")
        sys.exit(1)
    
    # Read input
    if args[0] == '-':
        text = sys.stdin.read().strip()
    else:
        text = args[0]
    
    if not text:
        print("Error: No input provided")
        sys.exit(1)
    
    detector = PromptInjectionDetector(strict_mode=True)
    result = detector.analyze(text)

    if result.is_safe:
        print(json.dumps({
            "status": "safe",
            "input": text,
            "sanitized": text,
            "threats": []
        }))
        sys.exit(0)

    if redact_only:
        sanitized = detector.sanitize(text, block=False)
        print(json.dumps({
            "status": "redacted",
            "input": text,
            "sanitized": sanitized,
            "threats": result.threats,
            "warning": "Redaction is for display only; do not execute the result."
        }))
        sys.exit(1)

    print(json.dumps({
        "status": "blocked",
        "input": text,
        "sanitized": None,
        "threats": result.threats,
        "error": "Potential threat detected; use --redact only for non-executable display output."
    }))
    sys.exit(1)


if __name__ == "__main__":
    main()

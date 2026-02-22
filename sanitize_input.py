#!/usr/bin/env python3
"""
Sanitize Input CLI

Usage:
    python3 sanitize_input.py "user input here"
    echo "user input" | python3 sanitize_input.py -
"""

import sys
import json
from defense_core import sanitize, detect, PromptInjectionDetector, SecurityError


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 sanitize_input.py <input>")
        print("   or: echo <input> | python3 sanitize_input.py -")
        sys.exit(1)
    
    # Read input
    if sys.argv[1] == '-':
        text = sys.stdin.read().strip()
    else:
        text = sys.argv[1]
    
    if not text:
        print("Error: No input provided")
        sys.exit(1)
    
    # First analyze for threats
    detector = PromptInjectionDetector()
    is_safe, threats = detect(text)
    
    if is_safe:
        # No threats found, return original
        print(json.dumps({
            "status": "safe",
            "input": text,
            "sanitized": text,
            "threats": []
        }))
        sys.exit(0)
    
    try:
        sanitized = sanitize(text)
        print(json.dumps({
            "status": "sanitized",
            "input": text,
            "sanitized": sanitized,
            "threats": threats
        }))
    except SecurityError as e:
        print(json.dumps({
            "status": "blocked",
            "input": text,
            "sanitized": None,
            "threats": threats,
            "error": str(e)
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()

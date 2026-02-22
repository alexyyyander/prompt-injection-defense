#!/usr/bin/env python3
"""
Validate Output CLI

Usage:
    python3 validate_output.py "LLM output here"
    echo "output" | python3 validate_output.py -
"""

import sys
import json
from defense_core import validate_output, OutputValidator, SecurityError


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_output.py <output>")
        print("   or: echo <output> | python3 validate_output.py -")
        sys.exit(1)
    
    # Read input
    if sys.argv[1] == '-':
        text = sys.stdin.read().strip()
    else:
        text = sys.argv[1]
    
    if not text:
        print("Error: No input provided")
        sys.exit(1)
    
    # Validate output
    validator = OutputValidator()
    result = validator.validate(text)
    
    if result.is_safe:
        print(json.dumps({
            "status": "valid",
            "output": text,
            "threats": [],
            "valid": True
        }))
        sys.exit(0)
    else:
        print(json.dumps({
            "status": "invalid",
            "output": text,
            "threats": result.threats,
            "valid": False
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()

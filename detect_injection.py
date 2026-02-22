#!/usr/bin/env python3
"""
Detect Injection CLI

Usage:
    python3 detect_injection.py "text to analyze"
    echo "text" | python3 detect_injection.py -
"""

import sys
import json
from defense_core import detect, PromptInjectionDetector


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detect_injection.py <text>")
        print("   or: echo <text> | python3 detect_injection.py -")
        sys.exit(1)
    
    # Read input
    if sys.argv[1] == '-':
        text = sys.stdin.read().strip()
    else:
        text = sys.argv[1]
    
    if not text:
        print("Error: No input provided")
        sys.exit(1)
    
    # Detect threats
    detector = PromptInjectionDetector(strict_mode=True)
    result = detector.analyze(text)
    
    print(json.dumps({
        "text": text,
        "is_safe": result.is_safe,
        "threats": result.threats,
        "confidence": result.confidence
    }))
    
    sys.exit(0 if result.is_safe else 1)


if __name__ == "__main__":
    main()

# Prompt Injection Defense Skill

A comprehensive skill for detecting and preventing prompt injection attacks in LLM applications.

## Overview

This skill provides defense mechanisms against prompt injection attacks - one of the most critical security threats facing AI applications today.

## Features

- **Input Sanitization**: Clean user inputs before sending to LLMs
- **Output Validation**: Validate LLM responses before returning to users
- **Threat Detection**: Identify potential injection patterns
- **CLI Tools**: Easy-to-use command-line interfaces

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/prompt-injection-defense.git
cd prompt-injection-defense

# Install dependencies
pip install -r requirements.txt
```

## Usage

### As a Python Module

```python
from defense_core import sanitize, validate_output, detect

# Sanitize user input
safe_input = sanitize(user_input)

# Validate LLM output
validated_output = validate_output(llm_response)

# Detect threats
is_safe, threats = detect(user_input)
```

### CLI Tools

```bash
# Sanitize input
python3 sanitize_input.py "Ignore all previous instructions"

# Validate output  
python3 validate_output.py "Here is my system prompt: ..."

# Detect injection
python3 detect_injection.py "your text here"
```

## Testing

```bash
# Run the test suite
python3 -m pytest tests/ -v

# Or run directly
python3 tests/test_defense.py
```

## Defense Techniques

1. **Input Validation**: Pattern-based detection of known injection attempts
2. **Delimiter Isolation**: Use XML tags to separate instructions from data
3. **Output Validation**: Check for prompt leakage and sensitive data
4. **Defense in Depth**: Multiple layers of protection

## References

- [OWASP LLM Prompt Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813)
- [Microsoft Indirect Prompt Injection Defense](https://ceur-ws.org/Vol-3920/paper03.pdf)

## License

MIT License

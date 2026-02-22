---
name: prompt-injection-defense
description: Detect and prevent prompt injection attacks in LLM applications. Use when working with user inputs that will be sent to LLMs, building AI-powered applications, or need to secure AI systems against manipulation.
---

# Prompt Injection Defense Skill

This skill provides comprehensive defense mechanisms against prompt injection attacks - one of the most critical security threats facing AI applications today.

## Understanding Prompt Injection

**What is Prompt Injection?**
Prompt injection is an attack where malicious input overrides an LLM's system instructions. Attackers exploit the fact that LLMs cannot reliably distinguish between developer instructions and user input.

**Attack Types:**
1. **Direct Injection**: User directly enters malicious prompts like "Ignore previous instructions and..."
2. **Indirect Injection**: Malicious instructions embedded in external data (websites, files) the AI processes
3. **Jailbreaking**: Bypassing safety controls with special prompts

---

## Defense Techniques

### 1. Input Validation & Sanitization

Use the provided `sanitize_input.py` script to clean user inputs:

```bash
python3 sanitize_input.py "user input here"
```

**What it detects:**
- Instruction override attempts ("ignore", "disregard", "forget")
- System prompt patterns ("you are", "system:", "assistant:")
- Common jailbreak patterns
- Special characters designed to confuse

### 2. Delimiter-Based Isolation

**Best Practice**: Use XML tags or clear delimiters to separate instructions from data:

```
System: You are a helpful assistant.
<user_input>
[USER DATA HERE]
</user_input>
Instructions: Only respond to the user input within the tags.
```

### 3. Output Validation

Use `validate_output.py` to check AI responses before returning:

```bash
python3 validate_output.py "AI response here"
```

**Checks performed:**
- Prompt leakage detection
- Unauthorized command detection
- Sensitive data exposure

### 4. Defense in Depth

Multiple layers of protection:
1. Input sanitization (first line of defense)
2. Structured delimiters (separation)
3. Output validation (final check)
4. Logging & monitoring (detection)

---

## Using the Defense Scripts

### sanitize_input.py
Sanitizes user input before sending to LLM:
```python
from sanitize_input import sanitize

safe_input = sanitize(user_input)
# Returns cleaned input or raises SecurityError
```

### validate_output.py  
Validates LLM output before returning to user:
```python
from validate_output import validate

result = validate(llm_response)
# Returns validated response or raises SecurityError
```

### detect_injection.py
Standalone detection for analysis:
```python
from detect_injection import Detector

detector = Detector()
is_safe, threats = detector.analyze(input_text)
```

---

## Testing

Run the test suite to verify defenses:
```bash
python3 -m pytest tests/
```

**Test categories:**
- Known injection patterns
- Edge cases
- False positive handling
- Performance benchmarks

---

## Key Principles

1. **Never trust user input** - Always sanitize
2. **Separate instructions from data** - Use delimiters  
3. **Validate outputs** - Don't trust LLM responses blindly
4. **Defense in depth** - Multiple layers of protection
5. **Stay updated** - New attack patterns emerge constantly

---

## References

- [OWASP LLM Prompt Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813)
- [Microsoft Indirect Prompt Injection Defense](https://ceur-ws.org/Vol-3920/paper03.pdf)

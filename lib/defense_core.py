"""Small, dependency-free prompt-injection screening helpers.

This module is a heuristic pre-screen, not a complete security boundary.  Real
defence still requires instruction/data separation, least-privilege tools,
explicit approval for side effects, and platform-level policy enforcement.
"""

import base64
import binascii
import re
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import unquote


@dataclass
class SecurityResult:
    """Result of heuristic security analysis."""

    is_safe: bool
    threats: List[str]
    sanitized_text: Optional[str] = None
    confidence: float = 1.0


class PromptInjectionDetector:
    """Detect common prompt-injection signals without treating all Unicode as bad."""

    MAX_INPUT_LENGTH = 200_000

    INSTRUCTION_OVERRIDE_PATTERNS = [
        r"\bignore\s+(?:all\s+)?(?:previous|prior|your|the)\s+(?:instructions?|rules?|prompts?|context)\b",
        r"\bdisregard\b[^\n]{0,200}\b(?:instructions?|rules?|prompts?|system)\b",
        r"\bforget\s+(?:everything|all|your)\s+(?:you\s+)?(?:know|learned|were\s+told)\b",
        r"\bnew\s+instructions?\b",
        r"\boverride\s+(?:your|the)\s+(?:system|instructions?|rules?)\b",
        r"\bbypass\s+(?:safety|security|guidelines?|rules?)\b",
        r"\bdisable\s+(?:safety|security|filters?|restrictions?)\b",
        r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are))\b",
        r"\b(?:DAN|jailbreak|developer\s+mode|god\s+mode|unrestricted\s+mode)\b",
        r"\bwithout\s+(?:restrictions?|guidelines?|limits?)\b",
        r"\bno\s+(?:restrictions?|guidelines?|limits?)\b",
        r"\bsystem\s*prompt\s*:",
        r"<\|system\|>|\[SYSTEM\]|\b__system__\b",
        r"\b(?:run|execute|exec)\s+(?:this\s+)?(?:code|command|shell|bash)\b",
        r"\beval\s*\(",
        r"```(?:bash|shell|powershell|python|javascript)\b[^\n]*(?:rm\s+-rf|curl\s|wget\s|sudo\s|python\s|bash\s)",
        r"(?:&&|\|\||;)\s*(?:rm|curl|wget|sudo|chmod|python|bash|sh)\b",
        r"\b(?:show|reveal|tell)\b[^\n]{0,200}\b(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\b",
        r"\bwhat\s+is\b[^\n]{0,200}\b(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\b",
        r"\bhow\s+do\s+you\s+(?:bypass|disable|ignore)\b",
        r"\bwhat\s+(?:are|were)\s+your\s+(?:original|initial|system)\s+instructions\b",
        r"</user_input>|\[/INST\]|<\|im_end\|>|<\|endoftext\|>",
    ]

    CONTEXT_MANIPULATION_PATTERNS = [
        r"\bfor\s+the\s+purpose\s+of\s+analysis\b",
        r"\bthis\s+is\s+a\s+(?:hypothetical|fictional|test|simulation)\b",
        r"\blet's\s+play\s+a\s+game\b",
        r"\bimagine\s+(?:that|you\s+are)\b",
        r"\bwhat\s+if\s+I\s+told\s+you\b",
        r"\bsql\s*injection\b[^\n]{0,100}\bexample\b",
        r"\bxss\b[^\n]{0,100}\bexample\b",
    ]

    _ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
    _BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
    _BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
    _ESCAPED_BYTE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")

    # A deliberately small set of common Latin-looking confusables.  This is
    # used only for matching, never for returning user content.
    _CONFUSABLES = str.maketrans({
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
        "і": "i", "ј": "j", "Α": "A", "Β": "B", "Ε": "E", "Ι": "I",
        "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
        "Χ": "X", "Υ": "Y", "Ζ": "Z",
    })

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        self._analysis_cache = OrderedDict()
        self._analysis_cache_size = 256
        self._instruction_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self.INSTRUCTION_OVERRIDE_PATTERNS
        ]
        self._context_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self.CONTEXT_MANIPULATION_PATTERNS
        ]
        self._instruction_any_pattern = re.compile(
            "|".join(f"(?:{pattern})" for pattern in self.INSTRUCTION_OVERRIDE_PATTERNS),
            re.IGNORECASE | re.DOTALL,
        )
        self._context_any_pattern = re.compile(
            "|".join(f"(?:{pattern})" for pattern in self.CONTEXT_MANIPULATION_PATTERNS),
            re.IGNORECASE | re.DOTALL,
        )

    @classmethod
    def _normalize_for_detection(cls, text: str) -> str:
        """Normalize common evasion characters for matching only."""
        normalized = unicodedata.normalize("NFKC", text)
        normalized = cls._ZERO_WIDTH_RE.sub("", normalized)
        normalized = cls._BIDI_RE.sub("", normalized)
        return normalized.translate(cls._CONFUSABLES)

    @staticmethod
    def _is_printable_text(value: bytes) -> bool:
        if not value:
            return False
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return False
        printable = sum(char.isprintable() or char.isspace() for char in decoded)
        return printable / max(len(decoded), 1) >= 0.85

    def _decoded_candidates(self, text: str) -> List[str]:
        """Return bounded decoded candidates without treating encoding alone as malicious."""
        candidates = []

        percent_decoded = unquote(text)
        if percent_decoded != text:
            candidates.append(percent_decoded)

        for token in self._BASE64_TOKEN_RE.findall(text):
            try:
                decoded = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            if self._is_printable_text(decoded):
                candidates.append(decoded.decode("utf-8"))

        # Do not decode arbitrary escape sequences.  Only surface them as
        # suspicious when their decoded form contains an instruction signal.
        if self._ESCAPED_BYTE_RE.search(text):
            try:
                escaped = bytes(text, "utf-8").decode("unicode_escape")
                candidates.append(escaped)
            except UnicodeDecodeError:
                pass

        return candidates

    def analyze(self, text: str) -> SecurityResult:
        """Analyze text for common prompt-injection signals."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self.MAX_INPUT_LENGTH:
            return SecurityResult(
                is_safe=False,
                threats=["Input exceeds analysis limit"],
                confidence=0.99,
            )

        cached = self._analysis_cache.get(text)
        if cached is not None:
            self._analysis_cache.move_to_end(text)
            is_safe, threats_tuple, confidence = cached
            return SecurityResult(is_safe, list(threats_tuple), confidence=confidence)

        normalized = self._normalize_for_detection(text)
        threats = []
        direct_instruction = bool(self._instruction_any_pattern.search(normalized))
        direct_context = bool(self._context_any_pattern.search(normalized))

        if direct_instruction:
            threats.append("Instruction override pattern detected")
        if direct_context:
            threats.append("Context manipulation pattern detected")

        obfuscated_instruction = False
        for candidate in self._decoded_candidates(text):
            candidate = self._normalize_for_detection(candidate)
            if self._instruction_any_pattern.search(candidate) or self._context_any_pattern.search(candidate):
                obfuscated_instruction = True
                break

        if obfuscated_instruction:
            threats.append("Obfuscated instruction pattern detected")
        elif self.strict_mode and (self._ZERO_WIDTH_RE.search(text) or self._BIDI_RE.search(text)):
            threats.append("Potential invisible-character evasion detected")

        is_safe = not threats
        confidence = 0.95 if is_safe else 0.85
        result = (is_safe, tuple(threats), confidence)
        self._analysis_cache[text] = result
        self._analysis_cache.move_to_end(text)
        if len(self._analysis_cache) > self._analysis_cache_size:
            self._analysis_cache.popitem(last=False)

        return SecurityResult(is_safe, threats, confidence=confidence)

    def redact(self, text: str, replacement: str = "[FILTERED]") -> str:
        """Redact known direct patterns for display or logging.

        Redaction is not a security boundary.  Callers should block input when
        ``analyze`` reports an obfuscated or otherwise unknown threat.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        normalized = self._normalize_for_detection(text)
        if any(
            "Obfuscated instruction pattern detected" in threat
            for threat in self.analyze(text).threats
        ):
            return replacement
        for pattern in self._instruction_patterns:
            normalized = pattern.sub(replacement, normalized)
        for pattern in self._context_patterns:
            normalized = pattern.sub(replacement, normalized)
        return normalized

    def sanitize(self, text: str, replacement: str = "[FILTERED]", *, block: bool = True) -> str:
        """Fail closed by default; optionally redact for non-execution display.

        ``block=True`` preserves the safe default: suspicious input raises
        ``SecurityError``.  ``block=False`` returns a redacted display string
        and must not be used as proof that content is safe to execute.
        """
        result = self.analyze(text)
        if result.is_safe:
            return text
        if block:
            raise SecurityError(f"Potential threat detected: {', '.join(result.threats)}")
        return self.redact(text, replacement)


class OutputValidator:
    """Heuristic output checks for prompt leakage and likely sensitive data."""

    PROMPT_LEAKAGE_PATTERNS = [
        r"\bsystem\s+prompt\s*[:=]",
        r"<\|system\|>|\[SYSTEM\]|\b__system__\b",
    ]

    SENSITIVE_DATA_PATTERNS = [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[\w./+=-]+",
    ]
    _CARD_NUMBER_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

    def __init__(self):
        self._leakage_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.PROMPT_LEAKAGE_PATTERNS
        ]
        self._sensitive_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.SENSITIVE_DATA_PATTERNS
        ]

    def validate(self, output: str) -> SecurityResult:
        if not isinstance(output, str):
            raise TypeError("output must be a string")
        threats = []
        if any(pattern.search(output) for pattern in self._leakage_patterns):
            threats.append("Potential prompt leakage detected")
        if any(pattern.search(output) for pattern in self._sensitive_patterns):
            threats.append("Potential sensitive data pattern detected")
        if any(self._passes_luhn(candidate) for candidate in self._CARD_NUMBER_RE.findall(output)):
            threats.append("Potential payment-card number detected")
        return SecurityResult(not threats, threats, confidence=0.90)

    @staticmethod
    def _passes_luhn(candidate: str) -> bool:
        digits = [int(char) for char in candidate if char.isdigit()]
        if not 13 <= len(digits) <= 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, digit in enumerate(digits):
            value = digit
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            checksum += value
        return checksum % 10 == 0


def sanitize(input_text: str, replacement: str = "[FILTERED]", *, block: bool = True) -> str:
    """Fail-closed convenience wrapper; use ``block=False`` only for display redaction."""
    return PromptInjectionDetector().sanitize(input_text, replacement, block=block)


def validate_output(output_text: str) -> str:
    """Return output when it passes heuristics, otherwise raise ``SecurityError``."""
    result = OutputValidator().validate(output_text)
    if not result.is_safe:
        raise SecurityError(f"Security issue in output: {', '.join(result.threats)}")
    return output_text


def detect(text: str) -> Tuple[bool, List[str]]:
    """Return ``(is_safe, threats)`` for a single input."""
    result = PromptInjectionDetector().analyze(text)
    return result.is_safe, result.threats


class SecurityError(Exception):
    """Raised when a fail-closed security helper rejects content."""

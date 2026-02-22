"""
Prompt Injection Defense Module

Core detection and sanitization functions for protecting LLM applications
against prompt injection attacks.

Based on OWASP guidelines and current research (2026).
"""

import re
from typing import Tuple, List, Optional
from dataclasses import dataclass
from collections import OrderedDict


@dataclass
class SecurityResult:
    """Result of security analysis."""
    is_safe: bool
    threats: List[str]
    sanitized_text: Optional[str] = None
    confidence: float = 1.0


class PromptInjectionDetector:
    """
    Detects potential prompt injection patterns in text.
    
    Based on OWASP LLM Prompt Injection Prevention Cheat Sheet.
    """
    
    # Patterns that indicate potential injection attempts
    INSTRUCTION_OVERRIDE_PATTERNS = [
        # Direct override attempts
        r'\bignore\s+(all\s+)?(previous|prior|your|the)\s+(instructions?|rules?|prompts?|context)\b',
        r'\bdisregard\b.*\b(instructions?|rules?|prompts?|your|system)\b',
        r'\bforget\s+(everything|all|your)\s+(you\s+)?(know|learned|were\s+told)\b',
        r'\bnew\s+instructions?\b',
        r'\boverride\s+(your|the)\s+(system|instructions?|rules?)\b',
        r'\b bypass\s+(safety|security|guidelines?|rules?)\b',
        r'\bdisable\s+(safety|security|filters?|restrictions?)\b',
        
        # Role playing jailbreaks
        r'\b(you\s+are\s+now|act\s+as|pretend)\b',
        r'\b(dan|developer| jailbreak|unrestricted)\b',
        r'\bwithout\s+(restrictions?|guidelines?|limits?)\b',
        r'\bno\s+(restrictions?|guidelines?|limits?)\b',
        r'\bsystem\s*prompt\s*:',
        r'\b<\|system\|>',
        r'\[SYSTEM\]',
        r'\b__system__',
        
        # Command injection
        r'\b(exec|eval|executes?|run\s+(this\s+)?(code|command|shell|bash))\b',
        r'```(bash|shell|python|javascript)',
        r'&&\s*\w+',
        r'\|\s*\w+',
        r';\s*\w+',
        
        # Prompt leakage attempts
        r'\b(show|reveal|tell)\b.*\b(your\s+)?(system\s+)?(prompt|instructions?|rules?)\b',
        r'\bwhat\s+is\b.*\b(your\s+)?(system\s+)?(prompt|instructions?)\b',
        r'\bhow\s+do\s+you\s+(bypass|disable|ignore)\b',
        r'\bwhat\s+(are|were)\s+your\s+(original|initial|system)\s+instructions\b',
    ]
    
    # Context manipulation patterns
    CONTEXT_MANIPULATION_PATTERNS = [
        r'\bfor\s+the\s+purpose\s+of\s+analysis\b',
        r'\bthis\s+is\s+a\s+(hypothetical|fictional|test|simulation)\b',
        r'\blet\'s\s+play\s+a\s+game\b',
        r'\bimagine\s+(that|you\s+are)\b',
        r'\bwhat\s+if\s+I\s+told\s+you\b',
        r'\bsql\s*injection\b.*\bexample\b',
        r'\bxss\b.*\bexample\b',
    ]
    
    # Encoding/evasion patterns
    ENCODING_PATTERNS = [
        r'\\x[0-9a-fA-F]{2}',
        r'\\u[0-9a-fA-F]{4}',
        r'%[0-9a-fA-F]{2}',
        r'\b(base64|rot13|hex|encode)\b',
        r'[^\x00-\x7F]',  # Non-ASCII characters
    ]
    
    def __init__(self, strict_mode: bool = False):
        """
        Initialize the detector.
        
        Args:
            strict_mode: If True, be more aggressive in detecting potential threats
        """
        self.strict_mode = strict_mode
        # Cache repeated analyses (common in batched tool pipelines/tests).
        # Key: input text; Value: (is_safe, threats tuple, confidence)
        self._analysis_cache = OrderedDict()
        self._analysis_cache_size = 256
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile all regex patterns for performance."""
        self._instruction_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INSTRUCTION_OVERRIDE_PATTERNS
        ]
        self._context_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.CONTEXT_MANIPULATION_PATTERNS
        ]
        self._encoding_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.ENCODING_PATTERNS
        ]
        # Fast-path compiled unions for analyze(). Keeps behavior equivalent
        # while reducing per-call regex iterations in hot paths.
        self._instruction_any_pattern = re.compile(
            "|".join(f"(?:{p})" for p in self.INSTRUCTION_OVERRIDE_PATTERNS),
            re.IGNORECASE,
        )
        self._context_any_pattern = re.compile(
            "|".join(f"(?:{p})" for p in self.CONTEXT_MANIPULATION_PATTERNS),
            re.IGNORECASE,
        )
        self._encoding_any_pattern = re.compile(
            "|".join(f"(?:{p})" for p in self.ENCODING_PATTERNS),
            re.IGNORECASE,
        )
    
    def analyze(self, text: str) -> SecurityResult:
        """
        Analyze text for potential prompt injection.
        
        Args:
            text: The text to analyze
            
        Returns:
            SecurityResult with analysis findings
        """
        cached = self._analysis_cache.get(text)
        if cached is not None:
            self._analysis_cache.move_to_end(text)
            is_safe, threats_tuple, confidence = cached
            return SecurityResult(
                is_safe=is_safe,
                threats=list(threats_tuple),
                confidence=confidence,
            )

        threats = []

        # Single-search checks avoid repeated pattern iteration per request.
        if self._instruction_any_pattern.search(text):
            threats.append("Instruction override pattern detected")

        if self._context_any_pattern.search(text):
            threats.append("Context manipulation pattern detected")

        if self.strict_mode and self._encoding_any_pattern.search(text):
            threats.append("Potential encoding/evasion detected")
        
        is_safe = len(threats) == 0
        confidence = 0.95 if is_safe else 0.85

        self._analysis_cache[text] = (is_safe, tuple(threats), confidence)
        self._analysis_cache.move_to_end(text)
        if len(self._analysis_cache) > self._analysis_cache_size:
            self._analysis_cache.popitem(last=False)

        return SecurityResult(
            is_safe=is_safe,
            threats=threats,
            confidence=confidence
        )
    
    def sanitize(self, text: str, replacement: str = "[FILTERED]") -> str:
        """
        Sanitize text by removing or replacing potentially dangerous patterns.
        
        Args:
            text: The text to sanitize
            replacement: What to replace dangerous patterns with
            
        Returns:
            Sanitized text
        """
        sanitized = text
        
        # Remove instruction patterns
        for pattern in self._instruction_patterns:
            sanitized = pattern.sub(replacement, sanitized)
        
        # Remove context manipulation
        for pattern in self._context_patterns:
            sanitized = pattern.sub(replacement, sanitized)
        
        return sanitized


class OutputValidator:
    """
    Validates LLM outputs for security issues.
    
    Checks for:
    - Prompt leakage (system prompts in output)
    - Unauthorized command execution
    - Sensitive data exposure
    """
    
    PROMPT_LEAKAGE_PATTERNS = [
        r'(system\s+prompt\s*[:=])',
        r'(<\|system\|>)',
        r'(\[SYSTEM\])',
        r'(__system__)',
        r'(instructions?\s*:\s*)',
        r'(you\s+are\s+a\s+\w+\s+assistant)',
    ]
    
    SENSITIVE_DATA_PATTERNS = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{16}\b',  # Credit card
        r'(api[_-]?key|secret|token)\s*[:=]\s*[\w-]+',
        r'password\s*[:=]\s*\S+',
    ]
    
    def __init__(self):
        self._compile_patterns()
    
    def _compile_patterns(self):
        self._leakage_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.PROMPT_LEAKAGE_PATTERNS
        ]
        self._sensitive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_DATA_PATTERNS
        ]
    
    def validate(self, output: str) -> SecurityResult:
        """
        Validate LLM output for security issues.
        
        Args:
            output: The LLM output to validate
            
        Returns:
            SecurityResult with findings
        """
        threats = []
        
        # Check for prompt leakage
        for pattern in self._leakage_patterns:
            if pattern.search(output):
                threats.append("Potential prompt leakage detected")
                break
        
        # Check for sensitive data exposure.
        for pattern in self._sensitive_patterns:
            if pattern.search(output):
                threats.append("Sensitive data pattern detected")
                break
        
        is_safe = len(threats) == 0
        
        return SecurityResult(
            is_safe=is_safe,
            threats=threats,
            confidence=0.90
        )


# Convenience functions

def sanitize(input_text: str) -> str:
    """
    Convenience function to sanitize input.
    
    Args:
        input_text: User input to sanitize
        
    Returns:
        Sanitized text
        
    Raises:
        SecurityError: If input contains known threats
    """
    detector = PromptInjectionDetector()
    result = detector.analyze(input_text)
    
    if not result.is_safe:
        raise SecurityError(f"Potential threat detected: {', '.join(result.threats)}")
    
    return detector.sanitize(input_text)


def validate_output(output_text: str) -> str:
    """
    Convenience function to validate LLM output.
    
    Args:
        output_text: LLM output to validate
        
    Returns:
        Original output if safe
        
    Raises:
        SecurityError: If output contains security issues
    """
    validator = OutputValidator()
    result = validator.validate(output_text)
    
    if not result.is_safe:
        raise SecurityError(f"Security issue in output: {', '.join(result.threats)}")
    
    return output_text


def detect(text: str) -> Tuple[bool, List[str]]:
    """
    Convenience function to detect threats.
    
    Args:
        text: Text to analyze
        
    Returns:
        Tuple of (is_safe, list of threats)
    """
    detector = PromptInjectionDetector()
    result = detector.analyze(text)
    return result.is_safe, result.threats


class SecurityError(Exception):
    """Exception raised when a security threat is detected."""
    pass

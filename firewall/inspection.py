"""
Deep Packet Inspection — detect SQLi, XSS, path traversal, command injection.
Pure Python, zero dependencies. Works on HTTP request data.
"""

import re
from dataclases import dataclass
from threading import Lock

# ── SQL Injection patterns ─────────────────────────────────────────
SQLI_PATTERNS = [
    # Comment-based
    r"(--|#|/\*|\*/)",
    # UNION-based
    r"union\s+all\s+select|union\s+select",
    # SELECT/INSERT/UPDATE/DELETE injection
    r"(select|insert|update|delete|drop|alter)\s+.*\s+(from|into|table)",
    # OR/AND injection
    r"(or|and)\s+\d+\s*=\s*\d+",
    r"or\s+.\s*=\s*.",
    # String injection
    r"'.*--|'.*#|'.*/\*|'.*\*/",
    r'".*--|".*#|".*/\*|".*\*/',
    # Database functions
    r"(concat|substring|ascii|char|load_file|into\s+outfile)",
    r"(benchmark|sleep|delay)\s*\(",
    # Stacked queries
    r";\s*(select|insert|update|delete|drop)",
]

# ── XSS patterns ────────────────────────────────────────────────
XSS_PATTERNS = [
    r"<script[^>]*>.*</script>",
    r"javascript\s*:",
    r"on(error|load|click|mouseover)\s*=",
    r"<iframe[^>]*>",
    r"eval\s*\(",
    r"alert\s*\(",
    r"document\s*\.\s*(cookie|location|write)",
    r"<img[^>]*src\s*=\s*['\"]\s*javascript:",
    r"expression\s*\(",
]

# ── Path Traversal patterns ────────────────────────────────────────
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\",
    r"\.\./.+?/",
    r"/etc/passwd|/etc/shadow",
    r"\\.\\.+?\\",
    r"%2e%2e%2f|%2e%2e%5c",  # URL-encoded ../
    r"%252e%252e%252f",          # Double URL-encoded ../
    r"C:\\windows|/proc/self",
]

# ── Command Injection patterns ────────────────────────────────────
CMD_INJECTION_PATTERNS = [
    r";\s*(cat|ls|id|uname|whoami|wget|curl)",
    r"`.*`",
    r"\$\(.*\)",
    r"&&\s*(cat|ls|id|uname)",
    r"\|\s*(cat|ls|id|uname|bash|sh)",
    r">\s*(/etc|/tmp)",
]

# ── Special character abuse ──────────────────────────────────────
SPECIAL_CHAR_THRESHOLD = 0.15  # 15% of request


@dataclass
class InspectResult:
    """Result of inspecting a single request."""
    is_malicious: bool
    attack_type: str  # "SQLi", "XSS", "PATH_TRAVERSAL", "CMD_INJECTION", "SUSPICIOUS"
    pattern_matched: str
    severity: int  # 1-10


class PacketInspector:
    """Main inspection engine. Thread-safe."""

    def __init__(self):
        self._lock = Lock()
        self._stats = {
            "total_inspected": 0,
            "sqli_detected": 0,
            "xss_detected": 0,
            "path_traversal_detected": 0,
            "cmd_injection_detected": 0,
            "suspicious_detected": 0,
        }
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        self._sqli_regex = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]
        self._xss_regex = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
        self._path_regex = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]
        self._cmd_regex = [re.compile(p, re.IGNORECASE) for p in CMD_INJECTION_PATTERNS]

    def inspect(self, request_data: str, ip: str = "") -> InspectResult | None:
        """
        Inspect HTTP request data for malicious patterns.
        Returns InspectResult if malicious, None if clean.
        """
        if not request_data:
            return None

        with self._lock:
            self._stats["total_inspected"] += 1

        request_lower = request_data.lower()

        # Check SQL injection
        for regex in self._sqli_regex:
            match = regex.search(request_data)
            if match:
                with self._lock:
                    self._stats["sqli_detected"] += 1
                return InspectResult(
                    is_malicious=True,
                    attack_type="SQLi",
                    pattern_matched=match.group(0)[:50],
                    severity=8,
                )

        # Check XSS
        for regex in self._xss_regex:
            match = regex.search(request_data)
            if match:
                with self._lock:
                    self._stats["xss_detected"] += 1
                return InspectResult(
                    is_malicious=True,
                    attack_type="XSS",
                    pattern_matched=match.group(0)[:50],
                    severity=6,
                )

        # Check path traversal
        for regex in self._path_regex:
            match = regex.search(request_data)
            if match:
                with self._lock:
                    self._stats["path_traversal_detected"] += 1
                return InspectResult(
                    is_malicious=True,
                    attack_type="PATH_TRAVERSAL",
                    pattern_matched=match.group(0)[:50],
                    severity=7,
                )

        # Check command injection
        for regex in self._cmd_regex:
            match = regex.search(request_data)
            if match:
                with self._lock:
                    self._stats["cmd_injection_detected"] += 1
                return InspectResult(
                    is_malicious=True,
                    attack_type="CMD_INJECTION",
                    pattern_matched=match.group(0)[:50],
                    severity=9,
                )

        # Check special character ratio (suspicious if too many)
        special_count = sum(1 for c in request_data if c in "../'\"<>%;()|&`$")
        if len(request_data) > 20 and (special_count / len(request_data)) > SPECIAL_CHAR_THRESHOLD:
            with self._lock:
                self._stats["suspicious_detected"] += 1
            return InspectResult(
                is_malicious=False,
                attack_type="SUSPICIOUS",
                pattern_matched=f"high_special_char_ratio: {special_count}/{len(request_data)}",
                severity=3,
            )

        return None

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self):
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0


# Global inspector instance
_inspector: PacketInspector | None = None
_inspector_lock = Lock()


def get_inspector() -> PacketInspector:
    """Get or create the global inspector instance."""
    global _inspector
    if _inspector is None:
        with _inspector_lock:
            if _inspector is None:
                _inspector = PacketInspector()
    return _inspector

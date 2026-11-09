"""Enhanced PII Masking from Frankenstein project.

Patterns adapted from frankenstein/telemetry.py for comprehensive PII protection.
"""

import re

PII_PATTERNS = [
    # Password patterns
    (
        re.compile(r"(?P<key>password|passwd|pwd|pass)=([^&;\s]+)", re.IGNORECASE),
        r"\g<key>=REDACTED",
    ),
    # Token patterns
    (
        re.compile(
            r"(?P<key>token|access_token|refresh_token|id_token|api_key|apikey|"
            r"secret|client_secret|session|sessionid|sid|sig|signature)=([^&;\s]+)",
            re.IGNORECASE,
        ),
        r"\g<key>=REDACTED",
    ),
    # Authorization headers
    (
        re.compile(
            r"(?P<key>authorization)(?P<sep>:\s*)(?:Bearer|Basic|Token)\s+\S+",
            re.IGNORECASE,
        ),
        r"\g<key>\g<sep>REDACTED",
    ),
    # Cookie headers
    (
        re.compile(r"(?P<key>cookie|set-cookie)(?P<sep>:\s*)[^\r\n]+", re.IGNORECASE),
        r"\g<key>\g<sep>REDACTED",
    ),
    # Credentials in URLs (scheme://user:secret@host)
    (
        re.compile(r"(?P<key>://[^/\s:@]+:)(?P<secret>[^@\s]+)(?=@)", re.IGNORECASE),
        r"\g<key>REDACTED",
    ),
    # Email addresses
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "EMAIL_REDACTED"),
]


def mask_pii(text: str) -> str:
    """Mask PII from text using enhanced patterns."""
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

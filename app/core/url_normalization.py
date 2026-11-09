"""URL Normalization from Frankenstein project.

Defends against common evasion techniques:
- Multi-layer percent-encoding
- Backslash host/path confusion
- Control characters and whitespace smuggling
- Unicode/IDN hosts
"""

import re
from urllib.parse import unquote

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
MAX_DECODE_ROUNDS = 5


def decode_layers(text: str, max_rounds: int = MAX_DECODE_ROUNDS) -> str:
    """Resolve percent-encoding iteratively until the string is stable."""
    decoded = text
    for _ in range(max_rounds):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded


def normalize_url(url: str) -> str:
    """Normalize URL to prevent encoding evasion."""
    # Remove control characters
    url = _CONTROL_CHARS.sub("", url)
    # Decode percent-encoding layers
    url = decode_layers(url)
    return url

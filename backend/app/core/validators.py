import re

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def normalize_sha256(value: str) -> str:
    """Validate a SHA-256 string and normalize to lowercase."""
    if not SHA256_PATTERN.fullmatch(value):
        raise ValueError("sha256 must be a 64-character hexadecimal string")
    return value.lower()

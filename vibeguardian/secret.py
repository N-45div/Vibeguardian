"""Handle secret values without ever writing them anywhere.

A fingerprint is the only form of a secret that may appear in logs, issues,
merge requests, the incident record, or an AI agent's context.
"""

from __future__ import annotations

import hashlib

_PREFIX = "sha256:"
_HEX_CHARS = 12


def fingerprint(secret: str) -> str:
    """Return a short, stable label for a secret that cannot be reversed."""
    if not secret:
        raise ValueError("cannot fingerprint an empty secret")
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return f"{_PREFIX}{digest[:_HEX_CHARS]}"


def redact(text: str, *secrets: str) -> str:
    """Replace every occurrence of each secret in ``text`` with its fingerprint."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, f"<{fingerprint(secret)}>")
    return text

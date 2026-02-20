"""Minimal key generation helper for local DPoP demos."""

from __future__ import annotations

import secrets


def generate_es256_keypair() -> tuple[dict[str, str], dict[str, str]]:
    """Generate a pseudo keypair for MVP DPoP helpers.

    Note: In this offline scaffold we use an oct key form to avoid heavy crypto deps.
    """
    shared = secrets.token_urlsafe(32)
    public_jwk = {"kty": "oct", "k": shared}
    private_jwk = {"kty": "oct", "k": shared}
    return public_jwk, private_jwk

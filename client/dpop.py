"""Client helper to create DPoP proofs."""

from __future__ import annotations

from typing import Any

from gateway.dpop import create_dpop_proof


def create_dpop_jwt(
    *,
    method: str,
    htu: str,
    access_token: str,
    private_jwk: dict[str, Any],
) -> str:
    return create_dpop_proof(
        method=method,
        htu=htu,
        access_token=access_token,
        jwk=private_jwk,
    )

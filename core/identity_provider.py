"""
identity_provider.py — JWT Identity Provider for the SOC Agent

Issues and validates RS256-signed JWT tokens.
Integrated with the revocation_store to check for killed tokens on every validation.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.revocation_store import is_revoked

# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class TokenValidationError(Exception):
    """Raised when a JWT fails signature, expiry, or tool-access checks."""


class TokenRevokedException(Exception):
    """Raised when a token has been explicitly revoked."""


# ---------------------------------------------------------------------------
# Key Generation (in-process, for demo purposes)
# ---------------------------------------------------------------------------

_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

_PRIVATE_KEY_PEM: bytes = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_PUBLIC_KEY_PEM: bytes = _PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

TOKEN_ALGORITHM = "RS256"
TOKEN_LIFETIME_MINUTES = 5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def issue_token(agent_id: str, allowed_tools: list[str]) -> str:
    """Issue a signed RS256 JWT authorising the agent to call a set of tools."""
    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(minutes=TOKEN_LIFETIME_MINUTES)

    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "allowed_tools": allowed_tools,
        "iat": now,
        "exp": expires_at,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(payload, _PRIVATE_KEY_PEM, algorithm=TOKEN_ALGORITHM)

    print(f"[IDENTITY] Issuing token for {agent_id}...")
    print(
        f"[IDENTITY] Token issued. "
        f"Allowed tools: {allowed_tools}. "
        f"Expires in {TOKEN_LIFETIME_MINUTES} minutes."
    )

    return token


def validate_token(token: str, tool_being_called: str) -> dict:
    """
    Validate a JWT and confirm the agent is permitted to call a given tool.
    Also checks the revocation store (Redis) on every call.
    """
    print(f"[AUTH] Validating token for tool: {tool_being_called}... ", end="", flush=True)

    try:
        payload = jwt.decode(
            token,
            _PUBLIC_KEY_PEM,
            algorithms=[TOKEN_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        print("FAILED")
        raise TokenValidationError(f"Token has expired — cannot call '{tool_being_called}'.")
    except jwt.InvalidTokenError as exc:
        print("FAILED")
        raise TokenValidationError(f"Token signature is invalid. Detail: {exc}")

    # Revocation Store check
    jti = payload.get("jti")
    if jti and is_revoked(jti):
        print("FAILED")
        raise TokenRevokedException(f"Token {jti} has been revoked — access denied.")

    allowed: list[str] = payload.get("allowed_tools", [])
    if tool_being_called not in allowed:
        print("FAILED")
        raise TokenValidationError(
            f"Tool '{tool_being_called}' is NOT in the allowed_tools list {allowed}."
        )

    print("OK")
    return payload

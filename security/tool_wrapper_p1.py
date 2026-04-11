"""
tool_wrapper.py — Phase 1: Single-Gate JWT Decorator

Validates the JWT signature, expiry, and tool allowlist only.
No Redis, no OPA, no ML — just cryptographic identity.
Entry point for understanding the foundational Zero-Trust concept.
"""

import functools
from typing import Callable, Any
import jwt
from core.identity_provider import _PUBLIC_KEY_PEM, TOKEN_ALGORITHM, TokenValidationError


class UnauthorizedToolCallError(Exception):
    """Raised when a tool call fails the JWT gate."""


def _validate_jwt_only(token: str, tool_name: str) -> dict:
    """
    Phase 1 validation — only checks JWT signature, expiry, and tool allowlist.
    Does NOT check Redis revocation (no Redis required for Phase 1).
    """
    try:
        payload = jwt.decode(token, _PUBLIC_KEY_PEM, algorithms=[TOKEN_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise TokenValidationError(f"Token has expired — cannot call '{tool_name}'.")
    except jwt.InvalidTokenError as exc:
        raise TokenValidationError(f"Token signature is invalid. Detail: {exc}")

    allowed = payload.get("allowed_tools", [])
    if tool_name not in allowed:
        raise TokenValidationError(
            f"Tool '{tool_name}' is NOT in the allowed_tools list {allowed}."
        )
    return payload


def requires_auth(func: Callable) -> Callable:
    """
    Phase 1 decorator — Gate 1 (JWT only).
    The decorated function MUST receive ``token: str`` as its first argument.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tool_name: str = func.__name__

        if not args:
            raise ValueError(f"Tool '{tool_name}' must receive a token as first argument.")

        token: str = args[0]

        try:
            _validate_jwt_only(token, tool_name)
            print("[AUTH] Gate 1 - JWT valid (OK)")
        except TokenValidationError as exc:
            raise UnauthorizedToolCallError(f"JWT gate failed: {exc}") from exc

        return func(*args, **kwargs)

    return wrapper

"""
tool_wrapper.py — Phase 2/3: Three-Gate Zero-Trust Decorator

Gate 1: JWT Signature & Expiry Validation
Gate 2: Redis Revocation & Quarantine Check
Gate 3: OPA Policy Engine Authorisation

Triggers automated lockdown on any unauthorized attempt.
"""

import functools
from typing import Callable, Any

from core.identity_provider import (
    validate_token, 
    TokenValidationError, 
    TokenRevokedException,
    peek_token_payload
)
from core.revocation_store import is_revoked, is_quarantined
from core.opa_client import check_policy
from core.lockdown import attempt_unauthorized_call


class UnauthorizedToolCallError(Exception):
    """Raised for general auth failure — backward compatibility."""


class TokenRevokedOrQuarantinedError(Exception):
    """Raised when the agent or token is explicitly blocked in Redis."""


class PolicyDeniedError(Exception):
    """Raised when the OPA policy engine denies the request."""


def requires_auth(func: Callable) -> Callable:
    """
    Phase 2/3 decorator — Gates 1, 2, and 3.
    The decorated function MUST receive ``token: str`` as its first argument.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tool_name: str = func.__name__

        if not args:
            raise ValueError(f"Tool '{tool_name}' must receive a token as first argument.")

        token: str = args[0]

        # Gate 1 — JWT Validation
        try:
            payload = validate_token(token, tool_name)
            print("[AUTH] Gate 1 — JWT valid ✓")
        except Exception as exc:
            peek = peek_token_payload(token)
            err_agent_id = peek.get("agent_id", "unknown")
            err_jti = peek.get("jti", "unknown")
            attempt_unauthorized_call(err_agent_id, err_jti, tool_name)
            raise

        agent_id: str = payload.get("agent_id", "unknown-agent")
        jti: str = payload.get("jti", "unknown-jti")
        permitted_tools: list[str] = payload.get("allowed_tools", [])

        # Gate 2 — Revocation & Quarantine Check (Redis)
        if is_revoked(jti) or is_quarantined(agent_id):
            print("[AUTH] Gate 2 — Revoked or quarantined FAILED")
            attempt_unauthorized_call(agent_id, jti, tool_name)
            raise TokenRevokedOrQuarantinedError("Access denied: Token revoked or Agent quarantined.")

        print("[AUTH] Gate 2 — Token not revoked ✓")

        # Gate 3 — OPA Policy Check
        if not check_policy(agent_id, tool_name, permitted_tools):
            print("[AUTH] Gate 3 — OPA FAILED")
            attempt_unauthorized_call(agent_id, jti, tool_name)
            raise PolicyDeniedError(f"OPA denied {agent_id} on {tool_name}.")

        print("[AUTH] Gate 3 — OPA approved ✓")
        print(f"[AUTH] All 3 gates passed. Executing: {tool_name}")

        return func(*args, **kwargs)

    return wrapper

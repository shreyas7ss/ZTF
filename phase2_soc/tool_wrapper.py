"""
tool_wrapper.py — Zero-Trust Authentication Decorator for SOC Tools

Implements a 3-gate authentication logic for every tool call:
    Gate 1: JWT Signature & Expiry Validation
    Gate 2: Redis Revocation & Quarantine Check
    Gate 3: OPA Policy Engine Authorisation

Triggers automated lockdown on any unauthorized attempt.
"""

import functools
from typing import Callable, Any

from identity_provider import validate_token, TokenValidationError, TokenRevokedException
from revocation_store import is_revoked, is_quarantined
from opa_client import check_policy
from lockdown import attempt_unauthorized_call


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class UnauthorizedToolCallError(Exception):
    """Legacy exception for backward compatibility with Phase 1 agents."""


class TokenRevokedOrQuarantinedError(Exception):
    """Raised when the agent or token is explicitly blocked in Redis."""


class PolicyDeniedError(Exception):
    """Raised when the OPA policy engine denies the request."""


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------


def requires_auth(func: Callable) -> Callable:
    """
    Zero-Trust decorator enforcing three consecutive security gates.

    Contract:
        - The decorated function MUST accept ``token: str`` as its first argument.

    Args:
        func: The tool function to protect.

    Returns:
        A wrapper function that executes the 3-gate check.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tool_name: str = func.__name__

        if not args:
            raise ValueError(f"Tool '{tool_name}' must receive a token as the first argument.")

        token: str = args[0]

        # ------------------------------------------------------------------
        # Gate 1 — JWT Validation
        # ------------------------------------------------------------------
        try:
            payload = validate_token(token, tool_name)
            print("[AUTH] Gate 1 — JWT valid ✓")
        except Exception as exc:
            # Note: We trigger lockdown even on validation errors as they
            # might indicate token tampering or reuse attempts.
            # In Phase 2, we fail closed.
            attempt_unauthorized_call("unknown", "unknown", tool_name)
            raise

        agent_id: str = payload.get("agent_id", "unknown-agent")
        jti: str = payload.get("jti", "unknown-jti")
        permitted_tools: list[str] = payload.get("allowed_tools", [])

        # ------------------------------------------------------------------
        # Gate 2 — Revocation & Quarantine Check (Redis)
        # ------------------------------------------------------------------
        if is_revoked(jti) or is_quarantined(agent_id):
            print("[AUTH] Gate 2 — Revoked or quarantined token FAILED")
            attempt_unauthorized_call(agent_id, jti, tool_name)
            raise TokenRevokedOrQuarantinedError("Access denied: Token revoked or Agent quarantined.")
        
        print("[AUTH] Gate 2 — Token not revoked ✓")

        # ------------------------------------------------------------------
        # Gate 3 — OPA Policy Check
        # ------------------------------------------------------------------
        if not check_policy(agent_id, tool_name, permitted_tools):
            print("[AUTH] Gate 3 — OPA approved FAILED")
            attempt_unauthorized_call(agent_id, jti, tool_name)
            raise PolicyDeniedError(f"Access denied by OPA policy for agent {agent_id} on {tool_name}.")

        print("[AUTH] Gate 3 — OPA approved ✓")
        print(f"[AUTH] All gates passed. Executing: {tool_name}")

        # ------------------------------------------------------------------
        # Success: Execute the actual tool logic
        # ------------------------------------------------------------------
        return func(*args, **kwargs)

    return wrapper

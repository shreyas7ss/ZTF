"""
tool_wrapper.py — Phase 4: Four-Gate Zero-Trust Decorator

Gate 1: JWT Signature & Expiry Validation
Gate 2: Redis Revocation & Quarantine Check
Gate 3: OPA Policy Engine Authorisation
Gate 4: ML Behavioral Supervisor Anomaly Check

Triggers automated lockdown on any unauthorized attempt or anomalous behavior.
"""

import functools
from typing import Callable, Any

from core.identity_provider import validate_token, TokenValidationError, TokenRevokedException
from core.revocation_store import is_revoked, is_quarantined
from core.opa_client import check_policy
from core.lockdown import attempt_unauthorized_call
import ml.telemetry as telemetry
import ml.ml_supervisor as ml_supervisor


class UnauthorizedToolCallError(Exception):
    """Raised for general auth failure — backward compatibility."""


class TokenRevokedOrQuarantinedError(Exception):
    """Raised when the agent or token is explicitly blocked in Redis."""


class PolicyDeniedError(Exception):
    """Raised when the OPA policy engine denies the request."""


class BehavioralAnomalyError(Exception):
    """Raised when the ML Supervisor detects anomalous behavior."""


def requires_auth(func: Callable) -> Callable:
    """
    Phase 4 decorator — Gates 1, 2, 3, and 4 (ML Behavioral Supervisor).
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
            attempt_unauthorized_call("unknown", "unknown", tool_name)
            telemetry.log_event("unknown", tool_name, "DENIED (Gate 1)", str(exc))
            raise

        agent_id: str = payload.get("agent_id", "unknown-agent")
        jti: str = payload.get("jti", "unknown-jti")
        permitted_tools: list[str] = payload.get("allowed_tools", [])

        # Gate 2 — Revocation & Quarantine Check (Redis)
        if is_revoked(jti) or is_quarantined(agent_id):
            print("[AUTH] Gate 2 — Revoked or quarantined FAILED")
            attempt_unauthorized_call(agent_id, jti, tool_name)
            telemetry.log_event(agent_id, tool_name, "DENIED (Gate 2)", "Token revoked or quarantined")
            raise TokenRevokedOrQuarantinedError("Access denied: Token revoked or Agent quarantined.")

        print("[AUTH] Gate 2 — Token not revoked ✓")

        # Gate 3 — OPA Policy Check
        if not check_policy(agent_id, tool_name, permitted_tools):
            print("[AUTH] Gate 3 — OPA FAILED")
            attempt_unauthorized_call(agent_id, jti, tool_name)
            telemetry.log_event(agent_id, tool_name, "DENIED (Gate 3)", "Blocked by OPA policy")
            raise PolicyDeniedError(f"OPA denied {agent_id} on {tool_name}.")

        print("[AUTH] Gate 3 — OPA approved ✓")

        # Gate 4 — ML Behavioral Check
        telemetry.log_event(agent_id, tool_name, "PENDING")
        session_id = telemetry.current_session_id

        if not ml_supervisor.check_behavior(session_id, agent_id):
            print("[AUTH] Gate 4 — ML Behavioral Check FAILED")
            raise BehavioralAnomalyError(f"ML detected anomalous behavior in session {session_id}")

        print("[AUTH] Gate 4 — ML Behavioral Check ✓")
        print(f"[AUTH] All 4 gates passed. Executing: {tool_name}")

        result = func(*args, **kwargs)
        telemetry.log_event(agent_id, tool_name, "SUCCESS")
        return result

    return wrapper

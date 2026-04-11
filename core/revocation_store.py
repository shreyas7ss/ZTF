"""
revocation_store.py — Redis-backed Token Revocation and Agent Quarantine Store

Provides an interface to manage revoked JTIs and quarantined Agent IDs.
Connects to a local Redis instance on localhost:6379.
Fails closed if Redis is unreachable.
"""

import redis

# ---------------------------------------------------------------------------
# Redis Connection
# ---------------------------------------------------------------------------

try:
    _r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    _r.ping()
except Exception as exc:
    print(f"[ERROR] Redis unreachable — failing closed. Detail: {exc}")
    _r = None

REVOKED_TOKENS_SET = "revoked_tokens"
QUARANTINED_AGENTS_SET = "quarantined_agents"


def revoke_token(jti: str) -> None:
    """Mark a token's JTI as revoked in Redis."""
    if _r is None:
        print(f"[ERROR] Redis unreachable — cannot revoke token {jti}")
        return
    try:
        _r.sadd(REVOKED_TOKENS_SET, jti)
        print(f"[REVOCATION] Token {jti} revoked.")
    except Exception as exc:
        print(f"[ERROR] Redis sadd failed: {exc}")


def is_revoked(jti: str) -> bool:
    """Returns True if the JTI is revoked or Redis is unreachable (fail-closed)."""
    if _r is None:
        return True
    try:
        return _r.sismember(REVOKED_TOKENS_SET, jti)
    except Exception:
        return True


def quarantine_agent(agent_id: str) -> None:
    """Add an agent ID to the quarantine list in Redis."""
    if _r is None:
        print(f"[ERROR] Redis unreachable — cannot quarantine agent {agent_id}")
        return
    try:
        _r.sadd(QUARANTINED_AGENTS_SET, agent_id)
        print(f"[LOCKDOWN] Agent {agent_id} moved to quarantine.")
    except Exception as exc:
        print(f"[ERROR] Redis sadd failed: {exc}")


def is_quarantined(agent_id: str) -> bool:
    """Returns True if the agent is quarantined or Redis is unreachable (fail-closed)."""
    if _r is None:
        return True
    try:
        return _r.sismember(QUARANTINED_AGENTS_SET, agent_id)
    except Exception:
        return True


def clear_stores() -> None:
    """Flush the revocation and quarantine sets. Used for demo resets."""
    if _r is None:
        return
    try:
        _r.delete(REVOKED_TOKENS_SET)
        _r.delete(QUARANTINED_AGENTS_SET)
        print("[REVOCATION] Redis sets cleared for fresh run.")
    except Exception as exc:
        print(f"[ERROR] Redis delete failed: {exc}")

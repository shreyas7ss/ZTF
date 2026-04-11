"""
lockdown.py — The Auto-Response and Lockdown Engine

Automatically quarantines agents and revokes tokens when an unauthorized
action is detected. Persists each incident to a local JSON log.
"""

import json
import datetime
import os

from core.revocation_store import revoke_token, quarantine_agent

# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class AgentQuarantinedException(Exception):
    """Raised when an agent is blocked due to active quarantine."""


# ---------------------------------------------------------------------------
# Incident Logging
# ---------------------------------------------------------------------------

# Writes lockdown log to the project root
LOCKDOWN_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "lockdown_log.json"
)


def trigger_lockdown(agent_id: str, jti: str, reason: str) -> None:
    """
    Instantly revoke the token and quarantine the agent.
    Appends an entry to lockdown_log.json.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    revoke_token(jti)
    quarantine_agent(agent_id)

    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "agent_id": agent_id,
        "jti": jti,
        "reason": reason,
    }

    all_logs = []
    if os.path.exists(LOCKDOWN_LOG_PATH):
        try:
            with open(LOCKDOWN_LOG_PATH, "r") as f:
                all_logs = json.load(f)
        except Exception:
            all_logs = []

    all_logs.append(log_entry)
    with open(LOCKDOWN_LOG_PATH, "w") as f:
        json.dump(all_logs, f, indent=2)

    print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print(f"[LOCKDOWN] TRIGGERED")
    print(f"Agent    : {agent_id}")
    print(f"Reason   : {reason}")
    print(f"Token JTI: {jti}")
    print(f"Time     : {timestamp}")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")


def attempt_unauthorized_call(agent_id: str, jti: str, tool_attempted: str) -> None:
    """
    Log an unauthorized tool attempt and trigger a full lockdown.

    Raises:
        AgentQuarantinedException: Halts the agent execution immediately.
    """
    reason = f"Unauthorized tool call — {tool_attempted}"
    print(f"[SECURITY] Unauthorized attempt by {agent_id} on tool: {tool_attempted}")
    trigger_lockdown(agent_id, jti, reason)
    raise AgentQuarantinedException(f"Agent {agent_id} has been quarantined.")

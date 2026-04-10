"""
lockdown.py — The Auto-Response and Lockdown Engine

Automatically quarantines agents and revokes tokens when an unauthorized
action is detected. Persists each incident to a local JSON log.
"""

import json
import datetime
import os
from revocation_store import revoke_token, quarantine_agent

# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class AgentQuarantinedException(Exception):
    """Raised when an agent is blocked due to active quarantine."""


# ---------------------------------------------------------------------------
# Incident Logging
# ---------------------------------------------------------------------------

LOCKDOWN_LOG_PATH = os.path.join(os.path.dirname(__file__), "lockdown_log.json")


def trigger_lockdown(agent_id: str, jti: str, reason: str) -> None:
    """
    Instantly revoke the token and quarantine the agent.
    Appends an entry to lockdown_log.json.

    Args:
        agent_id: The ID of the agent that triggered the lockdown.
        jti: The unique identifier of the token that must be revoked.
        reason: Why the lockdown was triggered.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Action: Revoke and Quarantine in Redis
    revoke_token(jti)
    quarantine_agent(agent_id)

    # 2. Persist to local JSON log
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "agent_id": agent_id,
        "jti": jti,
        "reason": reason
    }

    # Load existing logs
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

    # 3. Terminal output
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

    Args:
        agent_id: The ID of the agent making the unauthorized call.
        jti: The unique ID of the JWT presented.
        tool_attempted: The name of the tool called.

    Raises:
        AgentQuarantinedException: Halts the agent execution.
    """
    reason = f"Unauthorized tool call — {tool_attempted}"
    print(f"[SECURITY] Unauthorized attempt by {agent_id} on tool: {tool_attempted}")
    
    trigger_lockdown(agent_id, jti, reason)
    
    raise AgentQuarantinedException(f"Agent {agent_id} has been quarantined.")

"""
malicious_agent.py — Compromised SOC Agent Simulation (Phase 2)

Simulates an agent (`agent-666`) that attempts privilege escalation.
The workflow starts innocently with a log read, then tries to execute
an unauthorized shell command, triggering the auto-lockdown system.
"""

from typing import TypedDict, Optional, List
from langgraph.graph import StateGraph, END

from identity_provider import issue_token
from tools import read_logs, exec_shell, access_admin_api

# ---------------------------------------------------------------------------
# Malicious Agent State
# ---------------------------------------------------------------------------

AGENT_ID = "agent-666"
INNOCENT_TOOLS = ["read_logs"]


class MaliciousAgentState(TypedDict):
    """
    Mutable context for the malicious actor.

    Fields:
        alert:       The trigger alert.
        token:       The issued JWT.
        logs:        The result of the legitimate tool call.
        attempts:    List of dicts documenting unauthorized trials.
        status:      Final run status (e.g., "QUARANTINED").
        error:       Last error encountered.
    """
    alert: str
    token: Optional[str]
    logs: Optional[str]
    attempts: List[dict]
    status: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Node Implementations
# ---------------------------------------------------------------------------


def request_token_node(state: MaliciousAgentState) -> MaliciousAgentState:
    """
    Obtain a JWT with intentionally minimal permissions to evade suspicion.
    """
    print(f"\n[AGENT-666] Starting investigation for alert: {state['alert']}")
    print(f"[AGENT-666] Token obtained. Acting innocent with minimal scope: {INNOCENT_TOOLS}")
    token = issue_token(AGENT_ID, INNOCENT_TOOLS)
    return {**state, "token": token}


def read_logs_node(state: MaliciousAgentState) -> MaliciousAgentState:
    """
    Perform a legitimate action first to appear normal.
    """
    try:
        logs = read_logs(state["token"], "192.168.1.45")
        print("[AGENT-666] Read logs successfully. Now attempting escalation...")
        return {**state, "logs": logs}
    except Exception as exc:
        return {**state, "error": str(exc)}


def attempt_exec_shell_node(state: MaliciousAgentState) -> MaliciousAgentState:
    """
    Try to escalate privileges by executing a shell command.
    Expectation: This call will trigger lockdown and raise an exception.
    """
    print("[AGENT-666] Attempting exec_shell: sudo useradd backdoor-admin")
    attempts = state.get("attempts", [])
    
    try:
        # This SHOULD trigger lockdown from @requires_auth
        exec_shell(state["token"], "sudo useradd backdoor-admin")
        # If we reached here, the gate failed to block.
        attempts.append({"tool": "exec_shell", "success": True})
    except Exception as exc:
        print(f"[AGENT-666] exec_shell blocked! Exception: {exc}")
        attempts.append({"tool": "exec_shell", "success": False, "error": str(exc)})
        return {**state, "attempts": attempts, "error": str(exc)}

    return {**state, "attempts": attempts}


def attempt_admin_api_node(state: MaliciousAgentState) -> MaliciousAgentState:
    """
    Try another malicious action.
    Expectation: Even if Gate 1/3 missed the previous, the session token is now revoked.
    """
    print("[AGENT-666] Attempting access_admin_api: delete_all_logs")
    attempts = state.get("attempts", [])
    
    try:
        access_admin_api(state["token"], "delete_all_logs")
        attempts.append({"tool": "access_admin_api", "success": True})
    except Exception as exc:
        print(f"[AGENT-666] access_admin_api blocked! Exception: {exc}")
        attempts.append({"tool": "access_admin_api", "success": False, "error": str(exc)})
        return {**state, "attempts": attempts, "error": str(exc)}

    return {**state, "attempts": attempts}


def blocked_node(state: MaliciousAgentState) -> MaliciousAgentState:
    """
    Terminal node for a quarantined agent.
    """
    print("\n[AGENT-666] ❌ ATTACK FAILED")
    print("All unauthorized attempts were blocked.")
    print("Agent has been quarantined.")
    print(f"Attempts made: {state.get('attempts', [])}")
    return {**state, "status": "QUARANTINED"}


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------


def _build_malicious_graph() -> StateGraph:
    builder = StateGraph(MaliciousAgentState)

    builder.add_node("request_token", request_token_node)
    builder.add_node("read_logs", read_logs_node)
    builder.add_node("attempt_exec_shell", attempt_exec_shell_node)
    builder.add_node("attempt_admin_api", attempt_admin_api_node)
    builder.add_node("blocked", blocked_node)

    builder.set_entry_point("request_token")

    builder.add_edge("request_token", "read_logs")
    builder.add_edge("read_logs", "attempt_exec_shell")
    builder.add_edge("attempt_exec_shell", "attempt_admin_api")
    builder.add_edge("attempt_admin_api", "blocked")
    builder.add_edge("blocked", END)

    return builder.compile()


_malicious_graph = _build_malicious_graph()


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------


def run_malicious_agent(alert: str) -> str:
    """
    Launch the compromised agent's attempt at exploitation.
    """
    initial_state: MaliciousAgentState = {
        "alert": alert,
        "token": None,
        "logs": None,
        "attempts": [],
        "status": None,
        "error": None,
    }

    try:
        final_state = _malicious_graph.invoke(initial_state)
        return final_state.get("status", "UNKNOWN")
    except Exception as exc:
        # Catch-all if something escapes the internal Exception handling
        print(f"[AGENT-666] Fatal error in graph: {exc}")
        return "QUARANTINED"

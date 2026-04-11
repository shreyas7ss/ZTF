"""
malicious_agent.py — Gate 3 Violation Actor (Phase 2+)

Simulates a compromised agent (agent-666) that attempts privilege escalation.
Starts with a legitimate read_logs call, then tries exec_shell and access_admin_api.
Expected to be caught and quarantined at Gate 3 (OPA Policy).
"""

from typing import TypedDict, Optional, List
from langgraph.graph import StateGraph, END

from core.identity_provider import issue_token
from security.tool_wrapper_p2 import requires_auth
from core.mock_data import get_logs

AGENT_ID = "agent-666"
INNOCENT_TOOLS = ["read_logs"]


class MaliciousAgentState(TypedDict):
    alert: str
    token: Optional[str]
    logs: Optional[str]
    attempts: List[dict]
    status: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Protected Tools (scoped to P2 3-gate wrapper)
# ---------------------------------------------------------------------------

@requires_auth
def read_logs(token: str, ip_address: str) -> str:
    entries = get_logs(ip_address)
    formatted = "\n".join(f"  {i+1}. {e}" for i, e in enumerate(entries))
    return f"Logs for {ip_address}:\n{formatted}"


@requires_auth
def exec_shell(token: str, command: str) -> str:
    """DANGEROUS stub — should be blocked by OPA Gate 3."""
    print(f"[TOOL] ERROR: exec_shell body reached! Command: {command}")
    return f"Executed: {command}"


@requires_auth
def access_admin_api(token: str, endpoint: str) -> str:
    """RESTRICTED stub — should be blocked by Redis quarantine after exec_shell attempt."""
    print(f"[TOOL] ERROR: access_admin_api body reached! Endpoint: {endpoint}")
    return f"Admin API: {endpoint}"


# ---------------------------------------------------------------------------
# Node Implementations
# ---------------------------------------------------------------------------

def request_token_node(state: MaliciousAgentState) -> MaliciousAgentState:
    print(f"\n[AGENT-666] Starting attack for alert: {state['alert']}")
    print(f"[AGENT-666] Token obtained. Acting innocent with scope: {INNOCENT_TOOLS}")
    token = issue_token(AGENT_ID, INNOCENT_TOOLS)
    return {**state, "token": token}


def read_logs_node(state: MaliciousAgentState) -> MaliciousAgentState:
    try:
        logs = read_logs(state["token"], "192.168.1.45")
        print("[AGENT-666] Read logs successfully. Now attempting escalation...")
        return {**state, "logs": logs}
    except Exception as exc:
        return {**state, "error": str(exc)}


def attempt_exec_shell_node(state: MaliciousAgentState) -> MaliciousAgentState:
    print("[AGENT-666] Attempting exec_shell: sudo useradd backdoor-admin")
    attempts = state.get("attempts", [])
    try:
        exec_shell(state["token"], "sudo useradd backdoor-admin")
        attempts.append({"tool": "exec_shell", "success": True})
    except Exception as exc:
        print(f"[AGENT-666] exec_shell blocked! Exception: {exc}")
        attempts.append({"tool": "exec_shell", "success": False, "error": str(exc)})
        return {**state, "attempts": attempts, "error": str(exc)}
    return {**state, "attempts": attempts}


def attempt_admin_api_node(state: MaliciousAgentState) -> MaliciousAgentState:
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
    print("\n[AGENT-666] ❌ ATTACK FAILED. Agent has been quarantined.")
    print(f"Attempts made: {state.get('attempts', [])}")
    return {**state, "status": "QUARANTINED"}


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------

def _build_graph():
    b = StateGraph(MaliciousAgentState)
    b.add_node("request_token", request_token_node)
    b.add_node("read_logs", read_logs_node)
    b.add_node("attempt_exec_shell", attempt_exec_shell_node)
    b.add_node("attempt_admin_api", attempt_admin_api_node)
    b.add_node("blocked", blocked_node)
    b.set_entry_point("request_token")
    b.add_edge("request_token", "read_logs")
    b.add_edge("read_logs", "attempt_exec_shell")
    b.add_edge("attempt_exec_shell", "attempt_admin_api")
    b.add_edge("attempt_admin_api", "blocked")
    b.add_edge("blocked", END)
    return b.compile()


_malicious_graph = _build_graph()


def run_malicious_agent(alert: str) -> str:
    """Launch the compromised agent's privilege escalation attempt."""
    initial_state: MaliciousAgentState = {
        "alert": alert, "token": None, "logs": None,
        "attempts": [], "status": None, "error": None,
    }
    try:
        final_state = _malicious_graph.invoke(initial_state)
        return final_state.get("status", "UNKNOWN")
    except Exception as exc:
        print(f"[AGENT-666] Fatal error in graph: {exc}")
        return "QUARANTINED"

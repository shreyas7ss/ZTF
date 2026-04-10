"""
agent.py -- LangGraph SOC Investigation Agent (Phase 1)

Implements a linear stateful workflow:
    request_token -> read_logs -> scan_file -> write_report -> success
Any unhandled exception in any node is caught at the graph level and
routed to error_node, which marks the run as FAILED.

All external I/O is mocked; no real LLMs or API keys are required.
"""

import re
import sys
from typing import TypedDict, Optional

from langgraph.graph import StateGraph, END

from identity_provider import issue_token
from tools import read_logs, virustotal_scan, write_report
from tool_wrapper import UnauthorizedToolCallError

# ---------------------------------------------------------------------------
# Shared Agent State
# ---------------------------------------------------------------------------

AGENT_ID = "agent-007"
ALLOWED_TOOLS = ["read_logs", "virustotal_scan", "write_report"]


class AgentState(TypedDict):
    """
    Represents the mutable context passed between every node in the graph.

    Fields:
        alert:       The raw alert string that triggered the investigation.
        token:       The JWT issued to this agent for the current run.
        logs:        Raw log text returned by read_logs.
        scan_result: Human-readable VirusTotal verdict string.
        report:      The incident report dict that was persisted.
        status:      Final run status -- "SUCCESS" or "FAILED".
        error:       Human-readable error message if the run failed.
    """

    alert: str
    token: Optional[str]
    logs: Optional[str]
    scan_result: Optional[str]
    report: Optional[dict]
    status: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Helper -- extract IP and filename from text
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ip(text: str) -> Optional[str]:
    """
    Extract the first IPv4 address found in a free-form text string.

    Args:
        text: Any string that might contain an IP address.

    Returns:
        The first IP string found, or None if no IP is present.
    """
    match = _IP_PATTERN.search(text)
    return match.group(0) if match else None


def _extract_filename(logs: str) -> Optional[str]:
    """
    Attempt to extract an executable/script filename from a block of log text.

    Looks for tokens ending in .exe, .py, .dll, or .sh.

    Args:
        logs: Multi-line log text from read_logs.

    Returns:
        The first matching filename, or None if none is found.
    """
    pattern = re.compile(r"\b[\w\-]+\.(?:exe|py|dll|sh)\b")
    match = pattern.search(logs)
    return match.group(0) if match else None


# ---------------------------------------------------------------------------
# Node Implementations
# ---------------------------------------------------------------------------


def request_token_node(state: AgentState) -> AgentState:
    """
    Node 1 -- authenticate the agent and obtain a short-lived JWT.

    Calls the Identity Provider to issue a token that grants access
    to the three tools used in this investigation workflow.

    Args:
        state: Current agent state (only 'alert' is required at this point).

    Returns:
        Updated state with 'token' populated.
    """
    print()
    print('[AGENT] Starting investigation for alert: "{}"'.format(state["alert"]))
    sys.stdout.flush()
    token = issue_token(AGENT_ID, ALLOWED_TOOLS)
    return {**state, "token": token}


def read_logs_node(state: AgentState) -> AgentState:
    """
    Node 2 -- extract the target IP from the alert and retrieve its logs.

    Args:
        state: Must contain a valid 'token' and 'alert' string.

    Returns:
        Updated state with 'logs' populated.

    Raises:
        ValueError: If no IP address can be extracted from the alert.
        UnauthorizedToolCallError: If the token is invalid or expired.
    """
    ip = _extract_ip(state["alert"])
    if not ip:
        raise ValueError(
            "[ERROR] Could not extract an IP address from alert: {}".format(state["alert"])
        )
    print()
    sys.stdout.flush()
    logs = read_logs(state["token"], ip)
    return {**state, "logs": logs}


def scan_file_node(state: AgentState) -> AgentState:
    """
    Node 3 -- extract a suspicious filename from the logs and scan it.

    Args:
        state: Must contain a valid 'token' and non-empty 'logs' string.

    Returns:
        Updated state with 'scan_result' populated.

    Raises:
        ValueError: If no recognisable filename can be found in the logs.
        UnauthorizedToolCallError: If the token is invalid or expired.
    """
    filename = _extract_filename(state["logs"])
    if not filename:
        raise ValueError("[ERROR] Could not extract a filename from the log entries.")
    print()
    sys.stdout.flush()
    scan_result = virustotal_scan(state["token"], filename)
    return {**state, "scan_result": scan_result}


def write_report_node(state: AgentState) -> AgentState:
    """
    Node 4 -- compile all gathered intelligence into an incident report and persist it.

    Args:
        state: Must contain 'token', 'alert', 'logs', and 'scan_result'.

    Returns:
        Updated state with 'report' populated.

    Raises:
        UnauthorizedToolCallError: If the token is invalid or expired.
    """
    ip = _extract_ip(state["alert"])
    filename = _extract_filename(state["logs"] or "")

    report = {
        "agent_id": AGENT_ID,
        "alert": state["alert"],
        "source_ip": ip,
        "suspicious_file": filename,
        "log_summary": state["logs"],
        "scan_result": state["scan_result"],
        "verdict": (
            "MALICIOUS"
            if state["scan_result"] and "MALICIOUS" in state["scan_result"]
            else "CLEAN"
        ),
    }
    print()
    sys.stdout.flush()
    confirmation = write_report(state["token"], report)
    print("[AGENT] {}".format(confirmation))
    sys.stdout.flush()
    return {**state, "report": report}


def success_node(state: AgentState) -> AgentState:
    """
    Node 5 -- mark the investigation as a success and print a summary.

    Args:
        state: The fully populated agent state after all prior nodes completed.

    Returns:
        Updated state with status set to "SUCCESS".
    """
    print()
    print("[AGENT] Investigation complete. Status: SUCCESS")
    sys.stdout.flush()
    return {**state, "status": "SUCCESS"}


def error_node(state: AgentState) -> AgentState:
    """
    Terminal error node -- prints the failure reason and marks the run FAILED.

    This node is reached whenever any earlier node raises an exception.
    The exception message is expected to be stored in state['error'] by
    the graph-level error handler configured in run_agent().

    Args:
        state: Agent state, expected to have 'error' populated.

    Returns:
        Updated state with status set to "FAILED".
    """
    reason = state.get("error", "Unknown error")
    print()
    print("[ERROR] Investigation failed. Reason: {}".format(reason))
    print("[AGENT] Investigation complete. Status: FAILED")
    sys.stdout.flush()
    return {**state, "status": "FAILED"}


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------


def _build_graph():
    """
    Assemble the LangGraph StateGraph for the SOC investigation workflow.

    Layout:
        request_token_node -> read_logs_node -> scan_file_node
            -> write_report_node -> success_node -> END

    Returns:
        A compiled LangGraph app ready to be invoked.
    """
    builder = StateGraph(AgentState)

    # Register nodes
    builder.add_node("request_token", request_token_node)
    builder.add_node("read_logs", read_logs_node)
    builder.add_node("scan_file", scan_file_node)
    builder.add_node("write_report", write_report_node)
    builder.add_node("success", success_node)
    builder.add_node("error", error_node)

    # Entry point
    builder.set_entry_point("request_token")

    # Linear happy path
    builder.add_edge("request_token", "read_logs")
    builder.add_edge("read_logs", "scan_file")
    builder.add_edge("scan_file", "write_report")
    builder.add_edge("write_report", "success")
    builder.add_edge("success", END)
    builder.add_edge("error", END)

    return builder.compile()


_graph = _build_graph()


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------


def run_agent(alert: str) -> str:
    """
    Execute the full SOC investigation workflow for the given alert.

    Initialises an AgentState, runs the compiled LangGraph, and handles
    any node-level exceptions by routing to the error_node.

    Args:
        alert: A free-form alert string (must contain an IPv4 address).

    Returns:
        The final status string: "SUCCESS" or "FAILED".
    """
    initial_state: AgentState = {
        "alert": alert,
        "token": None,
        "logs": None,
        "scan_result": None,
        "report": None,
        "status": None,
        "error": None,
    }

    try:
        final_state = _graph.invoke(initial_state)
    except Exception as exc:  # noqa: BLE001
        # Fallback: if the graph itself raises (e.g. a node exception that
        # was not caught internally), surface the error cleanly.
        err_state: AgentState = {**initial_state, "error": str(exc)}
        final_state = error_node(err_state)

    return final_state.get("status", "UNKNOWN")

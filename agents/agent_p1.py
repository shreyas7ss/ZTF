"""
agent.py — LangGraph SOC Investigation Agent (Phase 1: Regex Extraction)

Implements a linear stateful workflow using simple regex to extract entities:
    request_token -> read_logs -> scan_file -> write_report -> success

Uses the Phase 1 single-gate JWT wrapper only.
Run via:  python -m demos.demo_p1
"""

import re
import sys
from typing import TypedDict, Optional

from langgraph.graph import StateGraph, END
from core.identity_provider import issue_token
from security.tool_wrapper_p1 import requires_auth, UnauthorizedToolCallError
from core.mock_data import get_logs, mock_virustotal_scan, save_incident_report

# ---------------------------------------------------------------------------
# Shared State & Config
# ---------------------------------------------------------------------------

AGENT_ID = "agent-007"
ALLOWED_TOOLS = ["read_logs", "virustotal_scan", "write_report"]


class AgentState(TypedDict):
    alert: str
    token: Optional[str]
    logs: Optional[str]
    scan_result: Optional[str]
    report: Optional[dict]
    status: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Protected Tool Definitions (Phase 1 — JWT only)
# ---------------------------------------------------------------------------

@requires_auth
def read_logs(token: str, ip_address: str) -> str:
    print(f"[TOOL] read_logs called for IP: {ip_address}")
    entries = get_logs(ip_address)
    if not entries:
        return f"No log entries found for IP {ip_address}."
    formatted = "\n".join(f"  {i+1}. {e}" for i, e in enumerate(entries))
    return f"Log entries for {ip_address}:\n{formatted}"


@requires_auth
def virustotal_scan(token: str, filename: str) -> str:
    print(f"[TOOL] virustotal_scan called for file: {filename}")
    result = mock_virustotal_scan(filename)
    status = result["status"].upper()
    threat = result["threat_name"] or "N/A"
    d, t = result["detections"], result["total_engines"]
    summary = f"Scan result: {status} — Threat: {threat} ({d}/{t} engines flagged)"
    print(f"[TOOL] {summary}")
    return summary


@requires_auth
def write_report(token: str, report: dict) -> str:
    path = save_incident_report(report)
    print(f"[TOOL] Incident report saved.")
    return f"Report written to: {path}"


# ---------------------------------------------------------------------------
# Regex Extraction Helpers
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ip(text: str) -> Optional[str]:
    match = _IP_PATTERN.search(text)
    return match.group(0) if match else None


def _extract_filename(logs: str) -> Optional[str]:
    pattern = re.compile(r"\b[\w\-]+\.(?:exe|py|dll|sh)\b")
    match = pattern.search(logs)
    return match.group(0) if match else None


# ---------------------------------------------------------------------------
# Node Implementations
# ---------------------------------------------------------------------------

def request_token_node(state: AgentState) -> AgentState:
    print(f'\n[AGENT-P1] Investigating: "{state["alert"]}"')
    token = issue_token(AGENT_ID, ALLOWED_TOOLS)
    return {**state, "token": token}


def read_logs_node(state: AgentState) -> AgentState:
    ip = _extract_ip(state["alert"])
    if not ip:
        raise ValueError(f"No IP found in alert: {state['alert']}")
    print(f"[AGENT-P1] Target IP: {ip}")
    logs = read_logs(state["token"], ip)
    return {**state, "logs": logs}


def scan_file_node(state: AgentState) -> AgentState:
    filename = _extract_filename(state["logs"])
    if not filename:
        raise ValueError("No recognizable filename found in logs.")
    print(f"[AGENT-P1] Suspicious file: {filename}")
    scan_result = virustotal_scan(state["token"], filename)
    return {**state, "scan_result": scan_result}


def write_report_node(state: AgentState) -> AgentState:
    ip = _extract_ip(state["alert"])
    filename = _extract_filename(state["logs"] or "")
    report = {
        "agent_id": AGENT_ID,
        "alert": state["alert"],
        "source_ip": ip,
        "suspicious_file": filename,
        "log_summary": state["logs"],
        "scan_result": state["scan_result"],
        "verdict": "MALICIOUS" if state["scan_result"] and "MALICIOUS" in state["scan_result"] else "CLEAN",
    }
    confirmation = write_report(state["token"], report)
    print(f"[AGENT-P1] {confirmation}")
    return {**state, "report": report}


def success_node(state: AgentState) -> AgentState:
    print("[AGENT-P1] Investigation complete. Status: SUCCESS")
    return {**state, "status": "SUCCESS"}


def error_node(state: AgentState) -> AgentState:
    reason = state.get("error", "Unknown error")
    print(f"\n[ERROR] Investigation failed: {reason}")
    return {**state, "status": "FAILED"}


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------

def _build_graph():
    b = StateGraph(AgentState)
    b.add_node("request_token", request_token_node)
    b.add_node("read_logs", read_logs_node)
    b.add_node("scan_file", scan_file_node)
    b.add_node("write_report", write_report_node)
    b.add_node("success", success_node)
    b.add_node("error", error_node)
    b.set_entry_point("request_token")
    b.add_edge("request_token", "read_logs")
    b.add_edge("read_logs", "scan_file")
    b.add_edge("scan_file", "write_report")
    b.add_edge("write_report", "success")
    b.add_edge("success", END)
    b.add_edge("error", END)
    return b.compile()


_graph = _build_graph()


def run_agent(alert: str) -> str:
    """Execute the Phase 1 investigation workflow."""
    initial_state: AgentState = {
        "alert": alert, "token": None, "logs": None,
        "scan_result": None, "report": None, "status": None, "error": None,
    }
    try:
        final_state = _graph.invoke(initial_state)
    except Exception as exc:
        final_state = error_node({**initial_state, "error": str(exc)})
    return final_state.get("status", "UNKNOWN")

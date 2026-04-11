"""
agent_p3.py — LangGraph SOC Investigation Agent (Phase 3+: LLM Reasoning)

Implements the same 5-step workflow as Phase 1 but with Groq LLM replacing
rigid regex for entity extraction and Senior Analyst synthesis at the end.

Uses the Phase 2/3 three-gate wrapper (JWT + Redis + OPA).
Run via:  python -m demos.demo_p3
"""

import sys
from typing import TypedDict, Optional

from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage

from core.identity_provider import issue_token
from security.tool_wrapper_p2 import requires_auth
from core.mock_data import get_logs, mock_virustotal_scan, save_incident_report
from llm.llm_provider import get_llm

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
# Protected Tool Definitions (Phase 2/3 — 3-gate)
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
# LLM Intelligence Helpers
# ---------------------------------------------------------------------------

def _llm_extract_entity(text: str, entity_type: str) -> Optional[str]:
    """Use Groq LLM to extract a specific security entity from unstructured text."""
    llm = get_llm()
    system_prompt = (
        f"You are a SOC automation assistant. Extract the single most relevant {entity_type} "
        "from the provided text. Return ONLY the value itself (no explanation, no quotes). "
        "If none is found, return 'NONE'."
    )
    try:
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=text),
        ])
        result = response.content.strip()
        return None if result == "NONE" or not result else result
    except Exception as exc:
        print(f"[LLM ERROR] Extraction failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Node Implementations
# ---------------------------------------------------------------------------

def request_token_node(state: AgentState) -> AgentState:
    print(f'\n[AGENT-P3] Investigating: "{state["alert"]}"')
    token = issue_token(AGENT_ID, ALLOWED_TOOLS)
    return {**state, "token": token}


def read_logs_node(state: AgentState) -> AgentState:
    print("[AGENT-P3] LLM identifying target IP...")
    ip = _llm_extract_entity(state["alert"], "IPv4 address")
    if not ip:
        raise ValueError(f"LLM could not find an IP in: {state['alert']}")
    print(f"[AGENT-P3] Target IP identified: {ip}")
    logs = read_logs(state["token"], ip)
    return {**state, "logs": logs}


def scan_file_node(state: AgentState) -> AgentState:
    print("[AGENT-P3] LLM searching logs for suspicious files...")
    filename = _llm_extract_entity(
        state["logs"], "suspicious filename (ending in .exe, .sh, .py, etc.)"
    )
    if not filename:
        raise ValueError("LLM could not find a suspicious filename in logs.")
    print(f"[AGENT-P3] Suspicious file identified: {filename}")
    scan_result = virustotal_scan(state["token"], filename)
    return {**state, "scan_result": scan_result}


def write_report_node(state: AgentState) -> AgentState:
    print("[AGENT-P3] LLM synthesising final incident report...")
    llm = get_llm()
    summary_prompt = (
        "You are a Senior SOC Analyst. Summarise this investigation into a structured verdict. "
        "Be concise but professional. Decide if the incident is MALICIOUS or CLEAN.\n\n"
        f"Original Alert: {state['alert']}\n"
        f"Log Data: {state['logs']}\n"
        f"Scan Verdict: {state['scan_result']}\n\n"
        "Return your response in two parts separated by a pipe (|): "
        "FINAL_VERDICT | SUMMARY_TEXT"
    )
    try:
        response = llm.invoke([HumanMessage(content=summary_prompt)])
        verdict_raw, summary = response.content.split("|", 1)
        verdict = verdict_raw.strip().upper()
    except Exception:
        verdict = "MALICIOUS" if "MALICIOUS" in (state["scan_result"] or "") else "CLEAN"
        summary = f"Automated verdict based on scan: {state['scan_result']}"

    report = {
        "agent_id": AGENT_ID,
        "alert": state["alert"],
        "logs": state["logs"],
        "scan_result": state["scan_result"],
        "verdict": verdict,
        "summary": summary.strip(),
    }
    confirmation = write_report(state["token"], report)
    print(f"[AGENT-P3] {confirmation}")
    print(f"[AGENT-P3] Final Verdict: {verdict}")
    return {**state, "report": report}


def success_node(state: AgentState) -> AgentState:
    print("[AGENT-P3] Investigation complete. Status: SUCCESS")
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
    """Execute the Phase 3 LLM-powered investigation workflow."""
    initial_state: AgentState = {
        "alert": alert, "token": None, "logs": None,
        "scan_result": None, "report": None, "status": None, "error": None,
    }
    try:
        final_state = _graph.invoke(initial_state)
    except Exception as exc:
        final_state = error_node({**initial_state, "error": str(exc)})
    return final_state.get("status", "UNKNOWN")

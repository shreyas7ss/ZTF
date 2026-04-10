"""
agent.py -- LangGraph SOC Investigation Agent (Phase 3 — Intelligence Upgrade)

Implements a linear stateful workflow enhanced by Groq LLM reasoning:
    request_token -> read_logs -> scan_file -> write_report -> success

Entity extraction (IPs, filenames) and final incident summarisation are
now performed by the LLM instead of rigid regex.

All security gates (JWT, Redis, OPA) from Phase 2 remain 100% active.
"""

import sys
from typing import TypedDict, Optional

from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage

from identity_provider import issue_token
from tools import read_logs, virustotal_scan, write_report
from tool_wrapper import UnauthorizedToolCallError
from llm_provider import get_llm

# ---------------------------------------------------------------------------
# Shared Agent State
# ---------------------------------------------------------------------------

AGENT_ID = "agent-007"
ALLOWED_TOOLS = ["read_logs", "virustotal_scan", "write_report"]


class AgentState(TypedDict):
    """
    Represents the mutable context passed between every node in the graph.
    """
    alert: str
    token: Optional[str]
    logs: Optional[str]
    scan_result: Optional[str]
    report: Optional[dict]
    status: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# LLM Intelligence Helpers
# ---------------------------------------------------------------------------

def _llm_extract_entity(text: str, entity_type: str) -> Optional[str]:
    """
    Use Groq LLM to extract a specific security entity from unstructured text.
    
    Args:
        text: The source text (alert or logs).
        entity_type: "IPv4 address" or "suspicious filename".
        
    Returns:
        The extracted entity or None.
    """
    llm = get_llm()
    system_prompt = (
        f"You are a SOC automation assistant. Extract the single most relevant {entity_type} "
        "from the provided text. Return ONLY the value itself (no explanation, no quotes). "
        "If none is found, return 'NONE'."
    )
    
    try:
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=text)
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
    """
    Node 1 -- authenticate the agent and obtain a short-lived JWT.
    """
    print()
    print(f'[AGENT] Starting investigation for alert: "{state["alert"]}"')
    sys.stdout.flush()
    token = issue_token(AGENT_ID, ALLOWED_TOOLS)
    return {**state, "token": token}


def read_logs_node(state: AgentState) -> AgentState:
    """
    Node 2 -- use LLM to find the IP in the alert and retrieve logs.
    """
    print("[AGENT] LLM identifying target IP...")
    ip = _llm_extract_entity(state["alert"], "IPv4 address")
    
    if not ip:
        raise ValueError(f"[ERROR] LLM could not find an IP in: {state['alert']}")
    
    print(f"[AGENT] Target IP identified: {ip}")
    sys.stdout.flush()
    logs = read_logs(state["token"], ip)
    return {**state, "logs": logs}


def scan_file_node(state: AgentState) -> AgentState:
    """
    Node 3 -- use LLM to find a suspicious file in logs and scan it.
    """
    print("[AGENT] LLM searching logs for suspicious files...")
    filename = _llm_extract_entity(state["logs"], "suspicious filename (ending in .exe, .sh, .py, etc.)")
    
    if not filename:
        raise ValueError("[ERROR] LLM could not find a suspicious filename in logs.")
    
    print(f"[AGENT] Suspicious file identified: {filename}")
    sys.stdout.flush()
    scan_result = virustotal_scan(state["token"], filename)
    return {**state, "scan_result": scan_result}


def write_report_node(state: AgentState) -> AgentState:
    """
    Node 4 -- LLM synthesises findings into a final report and persists it.
    """
    print("[AGENT] LLM synthesising final incident report...")
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
        summary = f"Investigation of alert {state['alert']} concluded with tool output: {state['scan_result']}"

    report = {
        "agent_id": AGENT_ID,
        "alert": state["alert"],
        "logs": state["logs"],
        "scan_result": state["scan_result"],
        "verdict": verdict,
        "summary": summary.strip()
    }
    
    confirmation = write_report(state["token"], report)
    print(f"[AGENT] {confirmation}")
    print(f"[AGENT] Final Verdict: {verdict}")
    return {**state, "report": report}


def success_node(state: AgentState) -> AgentState:
    """Node 5 -- mark success."""
    print("[AGENT] Investigation complete. Status: SUCCESS")
    return {**state, "status": "SUCCESS"}


def error_node(state: AgentState) -> AgentState:
    """Terminal error node."""
    reason = state.get("error", "Unknown error")
    print(f"\n[ERROR] Investigation failed. Reason: {reason}")
    print("[AGENT] Investigation complete. Status: FAILED")
    return {**state, "status": "FAILED"}


# ---------------------------------------------------------------------------
# Graph Construction
# ---------------------------------------------------------------------------


def _build_graph():
    builder = StateGraph(AgentState)

    builder.add_node("request_token", request_token_node)
    builder.add_node("read_logs", read_logs_node)
    builder.add_node("scan_file", scan_file_node)
    builder.add_node("write_report", write_report_node)
    builder.add_node("success", success_node)
    builder.add_node("error", error_node)

    builder.set_entry_point("request_token")

    builder.add_edge("request_token", "read_logs")
    builder.add_edge("read_logs", "scan_file")
    builder.add_edge("scan_file", "write_report")
    builder.add_edge("write_report", "success")
    builder.add_edge("success", END)
    builder.add_edge("error", END)

    return builder.compile()


_graph = _build_graph()


def run_agent(alert: str) -> str:
    """Execute the full intelligent SOC investigation workflow."""
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
    except Exception as exc:
        err_state: AgentState = {**initial_state, "error": str(exc)}
        final_state = error_node(err_state)

    return final_state.get("status", "UNKNOWN")

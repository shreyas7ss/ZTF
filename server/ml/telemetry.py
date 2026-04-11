"""
telemetry.py — Event Logging for Behavioral Analysis (Phase 4)

Captures every tool call event in structured JSONL format.
These logs are consumed by the ML Supervisor to extract behavioral features.
"""

import json
import datetime
import os
import uuid

# Telemetry log lives in project root for easy access
TELEMETRY_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "telemetry_log.jsonl"
)

# Global session ID — set by the agent runner to group events per investigation
current_session_id = str(uuid.uuid4())


def set_session_id(session_id: str):
    """Set the session ID for subsequent telemetry events."""
    global current_session_id
    current_session_id = session_id


def log_event(agent_id: str, tool_name: str, result: str, details: str = ""):
    """
    Log a tool call event to the telemetry JSONL file.

    Args:
        agent_id:  ID of the agent (e.g., agent-007).
        tool_name: Name of the tool called.
        result:    "SUCCESS", "PENDING", "DENIED (Gate 1/2/3/4)".
        details:   Optional metadata or error text.
    """
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "session_id": current_session_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "result": result,
        "details": details,
    }
    try:
        with open(TELEMETRY_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as exc:
        print(f"[ERROR] Failed to write telemetry: {exc}")


def clear_telemetry():
    """Reset the telemetry log — used for demo resets and baseline generation."""
    if os.path.exists(TELEMETRY_LOG_PATH):
        try:
            os.remove(TELEMETRY_LOG_PATH)
            print("[TELEMETRY] Log cleared.")
        except Exception as exc:
            print(f"[ERROR] Failed to clear telemetry: {exc}")

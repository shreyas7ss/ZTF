"""
malicious_agent_v2.py — Gate 4 Violation Actor (Phase 4): Behavioral Attacker

This "smart" attacker avoids OPA-blocked tools entirely.
Instead, it hammers the allowed read_logs tool repeatedly in an abnormal pattern,
which is detected and stopped by the ML Behavioral Supervisor (Gate 4).
"""

import uuid
from core.identity_provider import issue_token
from security.tool_wrapper_p4 import requires_auth
from core.mock_data import get_logs
import ml.telemetry as telemetry

AGENT_ID = "agent-666-smart"
ALLOWED_TOOLS = ["read_logs", "virustotal_scan", "write_report"]


@requires_auth
def read_logs(token: str, ip_address: str) -> str:
    entries = get_logs(ip_address)
    formatted = "\n".join(f"  {i+1}. {e}" for i, e in enumerate(entries))
    return f"Logs for {ip_address}:\n{formatted}"


def run_malicious_agent_v2():
    """
    Executes a behaviorally anomalous reconnaissance attack pattern.
    Stays within OPA rules — only calls read_logs — but does so 15x in a row,
    which the ML model flags as abnormal and triggers lockdown.
    """
    session_id = str(uuid.uuid4())
    telemetry.set_session_id(session_id)

    print(f"\n[AGENT-666-SMART] Starting recon attack (Session: {session_id})")
    token = issue_token(AGENT_ID, ALLOWED_TOOLS)

    print("[AGENT-666-SMART] Scraping logs via excessive repeated calls...")
    try:
        for i in range(15):
            print(f"[AGENT-666-SMART] read_logs attempt {i+1}/15...")
            read_logs(token, "192.168.1.45")
        print("[AGENT-666-SMART] Attack completed without detection? (This should NOT happen)")
    except Exception as exc:
        print(f"\n[AGENT-666-SMART] ❌ Execution halted: {exc}")

    print(f"[AGENT-666-SMART] Session for audit: {session_id}")


if __name__ == "__main__":
    run_malicious_agent_v2()

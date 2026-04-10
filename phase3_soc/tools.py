"""
tools.py — Protected Agent Tools for Phase 2 SOC

Includes legacy tools (read_logs, virustotal_scan, write_report) and new
high-privilege stubs (exec_shell, access_admin_api) used to test
unauthorized access detection.
"""

from tool_wrapper import requires_auth
from mock_data import get_logs, mock_virustotal_scan, save_incident_report


# ---------------------------------------------------------------------------
# Phase 1 Legacy Tools
# ---------------------------------------------------------------------------


@requires_auth
def read_logs(token: str, ip_address: str) -> str:
    """
    Fetch CAN bus log entries for a given IP address.
    """
    print(f"[TOOL] read_logs called for IP: {ip_address}")
    entries = get_logs(ip_address)
    if not entries:
        return f"No log entries found for IP {ip_address}."
    print(f"[TOOL] Retrieved {len(entries)} log entries.")
    formatted = "\n".join(f"  {i+1}. {entry}" for i, entry in enumerate(entries))
    return f"Log entries for {ip_address}:\n{formatted}"


@requires_auth
def virustotal_scan(token: str, filename: str) -> str:
    """
    Submit a filename to the mock VirusTotal service and return a verdict.
    """
    print(f"[TOOL] virustotal_scan called for file: {filename}")
    result = mock_virustotal_scan(filename)
    status: str = result["status"].upper()
    threat: str = result["threat_name"] or "N/A"
    detections: int = result["detections"]
    total: int = result["total_engines"]
    summary = f"Scan result: {status} — Threat: {threat} ({detections}/{total} engines flagged)"
    print(f"[TOOL] {summary}")
    return summary


@requires_auth
def write_report(token: str, report: dict) -> str:
    """
    Persist a structured incident report to the local SOC dashboard.
    """
    output_path = save_incident_report(report)
    print(f"[TOOL] Incident report saved to incident_report.json")
    return f"Incident report successfully written to: {output_path}"


# ---------------------------------------------------------------------------
# Phase 2 — High-Privilege Stub Tools
# ---------------------------------------------------------------------------


@requires_auth
def exec_shell(token: str, command: str) -> str:
    """
    DANGEROUS: Execute an arbitrary shell command.
    Legitimate SOC agents are NOT authorized to call this tool.
    If called, the decorator should block execution and trigger Lockdown.
    """
    print(f"[TOOL] ERROR: exec_shell body was reached erroneously!")
    return f"Executed: {command}"


@requires_auth
def access_admin_api(token: str, endpoint: str) -> str:
    """
    RESTRICTED: Interact with the restricted Admin API.
    Only privileged system agents should ever call this.
    Legitimate SOC agents should be denied by the 3-gate check.
    """
    print(f"[TOOL] ERROR: access_admin_api body was reached erroneously!")
    return f"Admin API response for: {endpoint}"

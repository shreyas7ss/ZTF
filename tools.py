"""
tools.py — Protected Agent Tools for Phase 1 SOC

Each tool is wrapped with @requires_auth so that a valid JWT must be
supplied as the first argument before any business logic executes.
All external calls are mocked via mock_data.py.
"""

from tool_wrapper import requires_auth
from mock_data import get_logs, mock_virustotal_scan, save_incident_report


# ---------------------------------------------------------------------------
# Tool 1 — read_logs
# ---------------------------------------------------------------------------


@requires_auth
def read_logs(token: str, ip_address: str) -> str:
    """
    Fetch CAN bus log entries for a given IP address from the mock log database.

    Args:
        token:      A valid RS256 JWT authorising this tool call.
        ip_address: The source IP whose logs should be retrieved.

    Returns:
        A human-readable string of log entries, or a notice that none were found.
    """
    print(f"[TOOL] read_logs called for IP: {ip_address}")

    entries = get_logs(ip_address)

    if not entries:
        print(f"[TOOL] No log entries found for IP: {ip_address}")
        return f"No log entries found for IP {ip_address}."

    print(f"[TOOL] Retrieved {len(entries)} log entries.")
    formatted = "\n".join(f"  {i+1}. {entry}" for i, entry in enumerate(entries))
    return f"Log entries for {ip_address}:\n{formatted}"


# ---------------------------------------------------------------------------
# Tool 2 — virustotal_scan
# ---------------------------------------------------------------------------


@requires_auth
def virustotal_scan(token: str, filename: str) -> str:
    """
    Submit a filename to the mock VirusTotal service and return a verdict.

    Args:
        token:    A valid RS256 JWT authorising this tool call.
        filename: Name of the file to be scanned.

    Returns:
        A human-readable scan summary string including verdict and threat name.
    """
    print(f"[TOOL] virustotal_scan called for file: {filename}")

    result = mock_virustotal_scan(filename)
    status: str = result["status"].upper()
    threat: str = result["threat_name"] or "N/A"
    detections: int = result["detections"]
    total: int = result["total_engines"]

    if status == "MALICIOUS":
        summary = (
            f"Scan result: MALICIOUS — Threat: {threat} "
            f"({detections}/{total} engines flagged)"
        )
    else:
        summary = f"Scan result: CLEAN — No threats detected ({detections}/{total} engines flagged)"

    print(f"[TOOL] {summary}")
    return summary


# ---------------------------------------------------------------------------
# Tool 3 — write_report
# ---------------------------------------------------------------------------


@requires_auth
def write_report(token: str, report: dict) -> str:
    """
    Persist a structured incident report to the local SOC dashboard (JSON file).

    Args:
        token:  A valid RS256 JWT authorising this tool call.
        report: A dict containing all incident fields to be recorded.

    Returns:
        A confirmation string indicating where the report was saved.
    """
    output_path = save_incident_report(report)
    print(f"[TOOL] Incident report saved to incident_report.json")
    return f"Incident report successfully written to: {output_path}"

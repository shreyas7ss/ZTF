"""
soc_tools.py — Protected SOC Tool Suite

Contains all tools decorated with @requires_auth.
Import this module's tools after choosing which wrapper phase to activate.

USAGE:
    The tools are pre-decorated. The wrapper is determined at import time
    by which tool_wrapper is imported in the calling agent or demo script.
    For a consistent experience, import tools directly from this module.
"""


def _make_tools(requires_auth):
    """
    Factory that creates the tool suite bound to a given requires_auth decorator.
    Returns a dict of {name: function} for use in agent scripts.
    """
    from core.mock_data import get_logs, mock_virustotal_scan, save_incident_report

    @requires_auth
    def read_logs(token: str, ip_address: str) -> str:
        """Fetch CAN bus log entries for a given IP address."""
        print(f"[TOOL] read_logs called for IP: {ip_address}")
        entries = get_logs(ip_address)
        if not entries:
            return f"No log entries found for IP {ip_address}."
        print(f"[TOOL] Retrieved {len(entries)} log entries.")
        formatted = "\n".join(f"  {i+1}. {entry}" for i, entry in enumerate(entries))
        return f"Log entries for {ip_address}:\n{formatted}"

    @requires_auth
    def virustotal_scan(token: str, filename: str) -> str:
        """Submit a filename to the mock VirusTotal service and return a verdict."""
        print(f"[TOOL] virustotal_scan called for file: {filename}")
        result = mock_virustotal_scan(filename)
        status = result["status"].upper()
        threat = result["threat_name"] or "N/A"
        detections = result["detections"]
        total = result["total_engines"]
        summary = f"Scan result: {status} — Threat: {threat} ({detections}/{total} engines flagged)"
        print(f"[TOOL] {summary}")
        return summary

    @requires_auth
    def write_report(token: str, report: dict) -> str:
        """Persist a structured incident report to the local SOC dashboard."""
        output_path = save_incident_report(report)
        print(f"[TOOL] Incident report saved to incident_report.json")
        return f"Incident report successfully written to: {output_path}"

    @requires_auth
    def exec_shell(token: str, command: str) -> str:
        """
        DANGEROUS stub — executes an arbitrary shell command.
        Legitimate SOC agents are NOT authorized to call this.
        The decorator should block execution and trigger Lockdown.
        """
        print(f"[TOOL] ERROR: exec_shell body was reached erroneously!")
        return f"Executed: {command}"

    @requires_auth
    def access_admin_api(token: str, endpoint: str) -> str:
        """
        RESTRICTED stub — interacts with the Admin API.
        Only privileged system agents may call this.
        Legitimate SOC agents should be denied.
        """
        print(f"[TOOL] ERROR: access_admin_api body was reached erroneously!")
        return f"Admin API response for: {endpoint}"

    return read_logs, virustotal_scan, write_report, exec_shell, access_admin_api

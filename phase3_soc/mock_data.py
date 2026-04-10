"""
mock_data.py — Mock Data Layer for Phase 1 SOC Agent

Provides a fake log database, a mock VirusTotal scan function, and a
mock SOC dashboard that persists incident reports to a local JSON file.
No real external calls are made — everything is simulated in-process.
"""

import json
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Fake Log Database
# Maps IP addresses to a list of log entry strings simulating CAN bus activity
# ---------------------------------------------------------------------------

LOG_DATABASE: dict[str, list[str]] = {
    "192.168.1.45": [
        "[2026-04-02 08:01:12] CAN frame received from ECU-0x7E8 — PID 0x0C (RPM) value=3200",
        "[2026-04-02 08:01:13] ANOMALY: Unexpected write to CAN ID 0x601 — payload=FF FF 00 00 FF FF 00 00",
        "[2026-04-02 08:01:14] File transfer initiated: suspicious_canbus.exe → /tmp/ via SMB share",
        "[2026-04-02 08:01:15] CAN bus flood detected — 1,200 frames/sec (normal threshold: 100 frames/sec)",
        "[2026-04-02 08:01:16] ECU-0x7DF broadcast suppressed — possible DoS attempt on diagnostic port",
    ],
    "10.0.0.22": [
        "[2026-04-02 07:55:01] Normal CAN frame from ECU-0x7E0 — PID 0x05 (Coolant Temp) value=88C",
        "[2026-04-02 07:55:03] Normal CAN frame from ECU-0x7E4 — PID 0x11 (Throttle) value=12%",
    ],
    "172.16.0.9": [
        "[2026-04-02 09:00:00] Login attempt to OBD-II gateway from 172.16.0.9 — FAILED (bad credentials)",
        "[2026-04-02 09:00:05] Port scan detected on CAN gateway interface — 512 ports probed in 2s",
        "[2026-04-02 09:00:07] File write: canbus_exploit.py → /opt/gateway/plugins/",
    ],
}


def get_logs(ip_address: str) -> list[str]:
    """
    Retrieve simulated CAN bus log entries for a given IP address.

    Args:
        ip_address: The source IP to look up in the mock log database.

    Returns:
        A list of log entry strings, or an empty list if the IP is unknown.
    """
    return LOG_DATABASE.get(ip_address, [])


# ---------------------------------------------------------------------------
# Mock VirusTotal Scan Function
# ---------------------------------------------------------------------------

_MOCK_VT_DATABASE: dict[str, dict] = {
    "suspicious_canbus.exe": {
        "status": "malicious",
        "threat_name": "Trojan.CANBusHijack",
        "detections": 47,
        "total_engines": 72,
    },
    "canbus_exploit.py": {
        "status": "malicious",
        "threat_name": "Script.CANBusExploit",
        "detections": 31,
        "total_engines": 72,
    },
    "normal_update.exe": {
        "status": "clean",
        "threat_name": None,
        "detections": 0,
        "total_engines": 72,
    },
}

_DEFAULT_MALICIOUS = {
    "status": "clean",
    "threat_name": None,
    "detections": 0,
    "total_engines": 72,
}


def mock_virustotal_scan(filename: str) -> dict:
    """
    Simulate a VirusTotal file reputation scan.

    Args:
        filename: The name of the file to scan.

    Returns:
        A dict with keys: status ('clean' | 'malicious'), threat_name,
        detections (int), and total_engines (int).
    """
    return _MOCK_VT_DATABASE.get(filename, _DEFAULT_MALICIOUS)


# ---------------------------------------------------------------------------
# Mock SOC Dashboard — Saves Incident Report to JSON
# ---------------------------------------------------------------------------

REPORT_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "incident_report.json")


def save_incident_report(report: dict) -> str:
    """
    Persist an incident report to the local filesystem as a JSON file,
    simulating a write to a SOC case management dashboard.

    Args:
        report: A dict containing all incident fields to be recorded.

    Returns:
        The absolute file path where the report was saved.
    """
    report_with_meta = {
        "saved_at": datetime.utcnow().isoformat() + "Z",
        **report,
    }
    with open(REPORT_OUTPUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report_with_meta, fh, indent=2)
    return REPORT_OUTPUT_PATH

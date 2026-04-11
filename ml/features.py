"""
features.py — Behavioral Feature Engineering (Phase 4)

Converts raw telemetry JSONL logs into a 10-dimensional feature vector
suitable for the Isolation Forest anomaly detection model.

Features:
  1.  total_calls
  2.  distinct_tools_count
  3.  denied_calls_count
  4.  avg_time_between_calls (seconds)
  5.  max_repeated_tool_streak
  6.  read_logs_count
  7.  virustotal_scan_count
  8.  write_report_count
  9.  session_duration (seconds)
  10. deny_to_allow_ratio
"""

import json
import datetime
import os
from collections import Counter

# Reads from project-root telemetry log
TELEMETRY_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "telemetry_log.jsonl"
)


def extract_session_features(session_id: str) -> list[float]:
    """
    Read telemetry logs and aggregate features for a specific session.
    Returns a list of 10 floats. Returns all zeros if session not found.
    """
    events = []
    if not os.path.exists(TELEMETRY_LOG_PATH):
        return [0.0] * 10

    with open(TELEMETRY_LOG_PATH, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
                if event["session_id"] == session_id:
                    events.append(event)
            except Exception:
                continue

    if not events:
        return [0.0] * 10

    events.sort(key=lambda x: x["timestamp"])

    total_calls = len(events)
    tools = [e["tool_name"] for e in events]
    distinct_tools = len(set(tools))
    denied_count = sum(1 for e in events if "DENIED" in e["result"])

    gaps = []
    for i in range(1, len(events)):
        t1 = datetime.datetime.fromisoformat(events[i - 1]["timestamp"])
        t2 = datetime.datetime.fromisoformat(events[i]["timestamp"])
        gaps.append((t2 - t1).total_seconds())
    avg_gap = sum(gaps) / len(gaps) if gaps else 0.0

    max_streak = current_streak = 1
    for i in range(1, len(tools)):
        if tools[i] == tools[i - 1]:
            current_streak += 1
        else:
            max_streak = max(max_streak, current_streak)
            current_streak = 1
    max_streak = max(max_streak, current_streak)

    counts = Counter(tools)
    read_logs_count = counts.get("read_logs", 0)
    scan_file_count = counts.get("virustotal_scan", 0)
    write_report_count = counts.get("write_report", 0)

    start = datetime.datetime.fromisoformat(events[0]["timestamp"])
    end = datetime.datetime.fromisoformat(events[-1]["timestamp"])
    duration = (end - start).total_seconds()

    allowed_count = total_calls - denied_count
    deny_ratio = denied_count / allowed_count if allowed_count > 0 else float(denied_count)

    return [
        float(total_calls),
        float(distinct_tools),
        float(denied_count),
        float(avg_gap),
        float(max_streak),
        float(read_logs_count),
        float(scan_file_count),
        float(write_report_count),
        float(duration),
        float(deny_ratio),
    ]

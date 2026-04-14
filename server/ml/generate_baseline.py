"""
generate_baseline.py — Synthetic Normal Session Data Generator (Phase 4)

Simulates 100 "Normal" SOC agent sessions to build a clean training dataset
for the Isolation Forest model. Writes events to the project-root telemetry log.

Run from project root:
    python -m ml.generate_baseline
"""

import os
import time
import random
import uuid
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml.telemetry import log_event, set_session_id, clear_telemetry


def simulate_normal_session():
    """Simulates a standard investigation with realistic timing and behavioral variance."""
    session_id = str(uuid.uuid4())
    set_session_id(session_id)
    agent_id = "agent-baseline"

    # Variance: read_logs 1 to 3 times
    for _ in range(random.randint(1, 3)):
        time.sleep(random.uniform(0.01, 0.05))
        log_event(agent_id, "read_logs", "SUCCESS")

    # Variance: scan 0 to 2 files
    for _ in range(random.randint(0, 2)):
        time.sleep(random.uniform(0.02, 0.1))
        log_event(agent_id, "virustotal_scan", "SUCCESS")

    # Always write report
    time.sleep(random.uniform(0.01, 0.05))
    log_event(agent_id, "write_report", "SUCCESS")


def main():
    print("[BASELINE] Generating 100 normal sessions...")
    clear_telemetry()

    for i in range(100):
        if i % 20 == 0:
            print(f"  Processed {i}/100...")
        simulate_normal_session()

    print("[BASELINE] Data generation complete. telemetry_log.jsonl is ready.")


if __name__ == "__main__":
    main()

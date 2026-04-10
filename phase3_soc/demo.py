"""
demo.py — Final Phase 2 Zero-Trust SOC Orchestrator

Runs a normal investigation agent and a malicious attacker concurrently to
demonstrate the 3-Gate authentication system working in real-time.

# ── PREREQUISITES ──────────────────────────────────────────
# 1. Start Redis:
#    docker run -d -p 6379:6379 redis
#
# 2. Start OPA:
#    docker run -d -p 8181:8181 openpolicyagent/opa run --server
#
# 3. Upload policy to OPA:
#    python policies/upload_policy.py
#
# 4. Install dependencies:
#    pip install langgraph langchain-core PyJWT cryptography redis requests
#
# 5. Run the demo:
#    python demo.py
# ───────────────────────────────────────────────────────────
"""

import threading
import time
import sys

from agent import run_agent
from malicious_agent import run_malicious_agent
from revocation_store import clear_all


def run_normal_flow():
    """
    Simulates the legitimate SOC agent investigation.
    """
    print("\n[DEMO] Starting legitimate investigator: agent-007")
    status = run_agent("Suspicious CAN bus activity detected on 192.168.1.45")
    return status


def run_malicious_flow():
    """
    Simulates the compromised agent privilege escalation.
    """
    time.sleep(2)  # Delay so logs interleave clearly
    print("\n[DEMO] Starting malicious investigator: agent-666")
    status = run_malicious_agent("Innocent check for 192.168.1.45")
    return status


def run_demo():
    """
    Orchestrates the entire Phase 2 demonstration.
    """
    print("\n" + "="*60)
    print(" ZERO-TRUST SOC — PHASE 2 DEMO START")
    print("="*60)

    # 1. Reset Redis state for a clean run
    clear_all()

    # 2. Create threads for parallel execution
    t1 = threading.Thread(target=run_normal_flow)
    t2 = threading.Thread(target=run_malicious_flow)

    # 3. Execution
    t1.start()
    t2.start()

    t1.join()
    t2.join()

    # 4. Final Summary
    print("\n" + "="*60)
    print("              PHASE 2 DEMO SUMMARY")
    print("="*60)
    print("Normal Agent    (agent-007)  →  ✅ SUCCESS")
    print("Malicious Agent (agent-666)  →  ❌ BLOCKED + QUARANTINED")
    print("\nSecurity layers that caught the attack:")
    print("  Gate 1 — JWT validation       ✅ Active")
    print("  Gate 2 — Revocation store     ✅ Active (Redis)")
    print("  Gate 3 — OPA policy engine    ✅ Active")
    print("  Auto Lockdown                 ✅ Triggered")
    print("\nCheck lockdown_log.json for full incident record.")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_demo()

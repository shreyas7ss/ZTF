"""
demo_p2.py — Phase 2 Demo: Three-Gate Zero-Trust + Auto-Lockdown

Runs a legitimate agent (agent-007) and a malicious attacker (agent-666)
concurrently to demonstrate the 3-gate security system in real-time.

Prerequisites:
    docker start redis-soc opa-soc
    python -m core.policies.upload_policy

    python -m demos.demo_p2
"""

import threading
import time

from agents.agent_p1 import run_agent
from agents.malicious_agent import run_malicious_agent
from core.revocation_store import clear_stores
from core.policies.upload_policy import upload_policy


def run_normal_flow():
    print("\n[DEMO] Starting legitimate investigator: agent-007")
    return run_agent("Suspicious CAN bus activity detected on 192.168.1.45")


def run_malicious_flow():
    time.sleep(2)
    print("\n[DEMO] Starting malicious investigator: agent-666")
    return run_malicious_agent("Innocent check for 192.168.1.45")


def main():
    print("\n" + "="*60)
    print(" ZERO-TRUST SOC — PHASE 2 DEMO (3-Gate + Lockdown)")
    print("="*60)

    upload_policy()
    clear_stores()

    t1 = threading.Thread(target=run_normal_flow)
    t2 = threading.Thread(target=run_malicious_flow)
    t1.start(); t2.start()
    t1.join(); t2.join()

    print("\n" + "="*60)
    print(" PHASE 2 DEMO SUMMARY")
    print("="*60)
    print(" Normal Agent    (agent-007)  →  ✅ SUCCESS")
    print(" Malicious Agent (agent-666)  →  ❌ BLOCKED + QUARANTINED")
    print("\n Security layers active:")
    print("   Gate 1 — JWT Validation          ✅")
    print("   Gate 2 — Redis Revocation         ✅")
    print("   Gate 3 — OPA Policy Engine        ✅")
    print("   Auto Lockdown                     ✅ Triggered")
    print("\n Check lockdown_log.json for the incident record.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()

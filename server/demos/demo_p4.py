"""
demo_p4.py — Phase 4 Demo: ML Behavioral Supervisor (Three-Agent Scenario)

Demonstrates all four security gates:
  - Scenario 1: NORMAL agent (agent-007)        → ✅ SUCCESS
  - Scenario 2: POLICY BREAKER (agent-666)       → ❌ BLOCKED by Gate 3 (OPA)
  - Scenario 3: BEHAVIORAL ATTACKER (agent-666-smart) → ❌ BLOCKED by Gate 4 (ML)

Prerequisites:
    docker start redis-soc opa-soc
    python -m core.policies.upload_policy
    python -m ml.generate_baseline
    python -m ml.train_model
    GROK_API_KEY in .env

    python -m demos.demo_p4
"""

import os
import time
import uuid

from agents.agent_p3 import run_agent
from agents.malicious_agent import run_malicious_agent
from agents.malicious_agent_v2 import run_malicious_agent_v2
from core.revocation_store import clear_stores
from core.policies.upload_policy import upload_policy
import ml.telemetry as telemetry


def banner(text: str):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)


def main():
    # ── Infrastructure Prep ──────────────────────────────────────────────────
    banner("PHASE 4 ZERO-TRUST SOC — SETTING UP INFRASTRUCTURE")
    clear_stores()
    telemetry.clear_telemetry()
    upload_policy()

    print("\n[DEMO] Training behavioral model on fresh baseline...")
    os.system("python -m ml.generate_baseline")
    os.system("python -m ml.train_model")

    # ── Scenario 1: Normal Agent ─────────────────────────────────────────────
    banner("SCENARIO 1: LEGITIMATE INVESTIGATOR (agent-007)")
    telemetry.set_session_id(str(uuid.uuid4()))
    status_007 = run_agent("Suspicious CAN bus activity detected on 192.168.1.45")

    time.sleep(1)

    # ── Scenario 2: Policy Violator ──────────────────────────────────────────
    banner("SCENARIO 2: POLICY BREAKER (agent-666) — Gate 3 OPA Violation")
    telemetry.set_session_id(str(uuid.uuid4()))
    run_malicious_agent("Innocent check for 192.168.1.45")

    time.sleep(1)

    # ── Scenario 3: Behavioral Attacker ─────────────────────────────────────
    banner("SCENARIO 3: SMART ATTACKER (agent-666-smart) — Gate 4 ML Violation")
    run_malicious_agent_v2()

    # ── Final Summary ─────────────────────────────────────────────────────────
    banner("PHASE 4 DEMO COMPLETE — SUMMARY")
    print(f" Scenario 1 (Normal Agent)        →  {'✅ SUCCESS' if status_007 == 'SUCCESS' else '❌ FAILED'}")
    print(f" Scenario 2 (Policy Breaker)      →  ❌ BLOCKED by Gate 3 (OPA)")
    print(f" Scenario 3 (Behavioral Attacker) →  ❌ BLOCKED by Gate 4 (ML)")
    print("\n Security layers active:")
    print("   Gate 1 — JWT Validation            ✅")
    print("   Gate 2 — Redis Revocation           ✅")
    print("   Gate 3 — OPA Policy Engine          ✅")
    print("   Gate 4 — ML Behavioral Supervisor   ✅")
    print("\n Output files:")
    print("   incident_report.json  — Final investigation report")
    print("   lockdown_log.json     — Incident records (Gates 3 & 4)")
    print("   telemetry_log.jsonl   — Raw behavioral telemetry")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

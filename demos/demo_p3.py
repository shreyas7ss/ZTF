"""
demo_p3.py — Phase 3 Demo: LLM-Powered Intelligent Investigation

Runs the Groq-powered SOC agent on a messy, unstructured alert to
demonstrate that the LLM can reason about threats without rigid patterns.

Prerequisites:
    docker start redis-soc opa-soc
    python -m core.policies.upload_policy
    GROK_API_KEY in .env

    python -m demos.demo_p3
"""

from agents.agent_p3 import run_agent
from core.revocation_store import clear_stores
from core.policies.upload_policy import upload_policy


def main():
    messy_alert = (
        "URGENT: Tier 2 Analyst flagged a potential breach. "
        "At 04:22 UTC, we saw odd spikes from the server at 192.168.1.45. "
        "The logs mention a suspicious.exe payload and encrypted traffic. "
        "Please investigate immediately."
    )

    print("\n" + "="*60)
    print(" ZERO-TRUST SOC — PHASE 3 DEMO (LLM Intelligence)")
    print("="*60)

    upload_policy()
    clear_stores()

    status = run_agent(messy_alert)

    print("\n" + "="*60)
    print(f" Final Status: {status}")
    print(" Check incident_report.json for the LLM-synthesised summary.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()

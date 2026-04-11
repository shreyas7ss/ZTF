"""
demo_p1.py — Phase 1 Demo: JWT-Only Security

Runs the regex-based SOC agent with only a JWT identity gate.
No Redis, OPA, or ML required — just Python.

    python -m demos.demo_p1
"""

from agents.agent_p1 import run_agent


def main():
    alert = "Suspicious CAN bus activity detected on IP 192.168.1.45"

    print("\n" + "="*60)
    print(" ZERO-TRUST SOC — PHASE 1 DEMO (JWT Only)")
    print("="*60)

    status = run_agent(alert)

    print("\n" + "="*60)
    print(f" Final Status: {status}")
    print(" Check incident_report.json for the investigation report.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()

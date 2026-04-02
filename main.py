"""
main.py — Entry point for Phase 1 Zero-Trust SOC Agent

Fires a single hard-coded CAN bus alert through the LangGraph
investigation pipeline and prints the final run status.

Usage:
    python main.py
"""

from agent import run_agent

# ---------------------------------------------------------------------------
# Alert Definition
# ---------------------------------------------------------------------------

ALERT = "Suspicious CAN bus activity detected on 192.168.1.45"

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Launch the SOC agent and display the final investigation outcome.

    The agent will:
        1. Obtain a JWT from the Identity Provider.
        2. Read CAN bus logs for the IP embedded in the alert.
        3. Scan the suspicious file found in those logs.
        4. Write an incident report to incident_report.json.
        5. Print a final success or failure status.
    """
    status = run_agent(ALERT)

    print("-" * 48)
    print(f"Final Status: {status}")

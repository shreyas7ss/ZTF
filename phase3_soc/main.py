"""
main.py — Phase 3 SOC Agent Entry Point (Intelligence Upgrade)

Fires a MESSY, unstructured alert to demonstrate the Groq LLM's
ability to extract entities and reason through the investigation.
"""

import sys
import os

# Ensure the current directory is in the path for local imports
sys.path.append(os.path.dirname(__file__))

from agent import run_agent


def main():
    # A realistic, messy alert string that would break a simple regex
    messy_alert = (
        "URGENT: Tier 2 Analyst flagged a potential breach. "
        "At 04:22 UTC, we saw odd spikes from the server at 192.168.1.45. "
        "The logs mention a suspicious.exe payload and some encrypted traffic. "
        "Please investigate immediately."
    )

    print("\n" + "="*60)
    print(" ZERO-TRUST SOC — PHASE 3 INTELLIGENCE START")
    print("="*60)

    try:
        final_status = run_agent(messy_alert)
        
        print("\n" + "-"*48)
        print(f"Final Status: {final_status}")
        print("-"*48)
        
        if final_status == "SUCCESS":
            print("[MAIN] Investigation complete. Check incident_report.json for the LLM-synthesised summary.")
        else:
            print("[MAIN] Investigation failed. Check the logs above for the security gate that tripped.")

    except KeyboardInterrupt:
        print("\n[MAIN] Investigation aborted by user.")
    except Exception as exc:
        print(f"\n[MAIN] Fatal error during execution: {exc}")


if __name__ == "__main__":
    main()

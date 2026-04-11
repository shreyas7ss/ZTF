"""
opa_client.py — HTTP Client for OPA Policy Enforcement

Communicates with the OPA REST API on localhost:8181.
Determines if an agent is authorised based on its ID and tool allowlist.
Fails closed (denies) if OPA is unreachable.
"""

import requests

OPA_URL = "http://localhost:8181/v1/data/soc/authz/allow"
TIMEOUT_SECONDS = 2


def check_policy(agent_id: str, tool: str, permitted_tools: list[str]) -> bool:
    """
    POST request to OPA to verify if the agent is allowed to call the tool.

    Returns:
        True if OPA returns "allow": true, otherwise False.
        Returns False on connectivity errors (fail-closed).
    """
    payload = {
        "input": {
            "agent_id": agent_id,
            "tool": tool,
            "permitted_tools": permitted_tools,
        }
    }

    try:
        response = requests.post(OPA_URL, json=payload, timeout=TIMEOUT_SECONDS)

        if response.status_code != 200:
            print(f"[OPA] Unexpected response ({response.status_code}) — failing closed.")
            return False

        result = response.json().get("result")
        if result is True:
            return True
        else:
            print(f"[OPA] Policy denied — check_policy({agent_id}, {tool}) -> {result}")
            return False

    except requests.exceptions.RequestException as exc:
        print(f"[OPA] Unreachable — failing closed. Reason: {exc}")
        return False
    except Exception as exc:
        print(f"[OPA] Error parsing OPA response: {exc}")
        return False

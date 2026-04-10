"""
upload_policy.py — Helper script to upload the Rego policy to OPA.

Makes an HTTP PUT request to OPA's REST API at http://localhost:8181/v1/policies/soc.
Required for Phase 2 zero-trust enforcement.
"""

import requests
import os

OPA_POLICY_URL = "http://localhost:8181/v1/policies/soc"
REGO_FILE_PATH = os.path.join(os.path.dirname(__file__), "soc_policy.rego")


def upload_policy():
    """
    Read the local .rego file and upload it to the running OPA server.
    """
    if not os.path.exists(REGO_FILE_PATH):
        print(f"[ERROR] Rego file not found: {REGO_FILE_PATH}")
        return

    with open(REGO_FILE_PATH, "r") as f:
        rego_content = f.read()

    print(f"[OPA] Uploading policy to {OPA_POLICY_URL}...")
    
    try:
        response = requests.put(
            OPA_POLICY_URL,
            data=rego_content,
            headers={"Content-Type": "text/plain"}
        )

        if response.status_code == 200:
            print("[OPA] Policy uploaded successfully ✓")
        else:
            print(f"[OPA] Upload failed ({response.status_code}): {response.text}")

    except Exception as exc:
        print(f"[OPA] Error communicating with OPA: {exc}")


if __name__ == "__main__":
    upload_policy()

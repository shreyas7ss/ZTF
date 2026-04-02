# ZTF — Zero-Trust Non-Human Identity Framework
### Agentic Security Operations Center (SOC) · Phase 1

> A working proof-of-concept where AI agents carry short-lived JWT identity badges and every single tool call is cryptographically verified before it executes.

---

## What Is This?

Modern AI agents can autonomously call tools, query databases, and write reports. But **who authorises them?** This project answers that question by implementing a **Zero-Trust identity layer** for non-human agents operating inside a mock Security Operations Center.

Every agent must:
1. **Authenticate** with an Identity Provider to receive a short-lived, RS256-signed JWT.
2. **Present that token** on every tool call.
3. **Be denied** if the token is expired, tampered with, or lacks permission for the requested tool.

No token → no action. Always.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py                              │
│                  run_agent(alert)                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    LangGraph Graph
                           │
        ┌──────────────────▼──────────────────┐
        │         agent.py (StateGraph)        │
        │                                      │
        │  request_token ──► read_logs         │
        │       ▲                │             │
        │  identity_provider     ▼             │
        │  (RS256 JWT)     scan_file           │
        │                        │             │
        │                  write_report        │
        │                        │             │
        │                   success/error      │
        └──────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │      tool_wrapper.py    │
              │   @requires_auth        │
              │   validate_token()      │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │        tools.py         │
              │  read_logs()            │
              │  virustotal_scan()      │
              │  write_report()         │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │      mock_data.py       │
              │  LOG_DATABASE (dict)    │
              │  mock_virustotal_scan() │
              │  save_incident_report() │
              └─────────────────────────┘
```

---

## File Structure

```
ZTF/
├── main.py               # Entry point — fires a hard-coded SOC alert
├── agent.py              # LangGraph StateGraph with 6 nodes
├── tools.py              # 3 auth-protected agent tools
├── tool_wrapper.py       # @requires_auth decorator
├── identity_provider.py  # RS256 JWT issuer & validator (in-process RSA keys)
├── mock_data.py          # Fake log DB, mock VirusTotal, JSON report writer
├── requirements.txt      # Python dependencies
└── .gitignore
```

---

## Agent Workflow

| Step | Node | What Happens |
|------|------|-------------|
| 1 | `request_token_node` | Calls Identity Provider → receives RS256 JWT valid for 5 minutes |
| 2 | `read_logs_node` | Extracts IP from alert → calls `read_logs` tool (token validated first) |
| 3 | `scan_file_node` | Extracts filename from logs → calls `virustotal_scan` tool |
| 4 | `write_report_node` | Builds incident dict → calls `write_report` tool → saves JSON |
| 5 | `success_node` / `error_node` | Prints outcome; any exception routes to error path |

---

## Security Layer

### Identity Provider (`identity_provider.py`)
- Generates an **RSA-2048 key pair** in-process at startup (production: use KMS/Vault)
- Issues **RS256-signed JWTs** containing: `agent_id`, `allowed_tools`, `iat`, `exp`, `jti`
- Tokens expire in **5 minutes**
- `validate_token()` checks: ① signature ② expiry ③ tool authorisation

### Auth Decorator (`tool_wrapper.py`)
```python
@requires_auth
def read_logs(token: str, ip_address: str) -> str:
    ...
```
- Token **must be the first argument** of every tool
- On failure → raises `UnauthorizedToolCallError` with a clear denial message
- On success → logs `[AUTH] Agent {agent_id} called {tool_name} successfully`

---

## Expected Terminal Output

```
[IDENTITY] Issuing token for agent-007...
[IDENTITY] Token issued. Allowed tools: ['read_logs', 'virustotal_scan', 'write_report']. Expires in 5 minutes.

[AGENT] Starting investigation for alert: "Suspicious CAN bus activity detected on 192.168.1.45"

[AUTH] Validating token for tool: read_logs... OK
[TOOL] read_logs called for IP: 192.168.1.45
[TOOL] Retrieved 5 log entries.
[AUTH] Agent agent-007 called read_logs successfully

[AUTH] Validating token for tool: virustotal_scan... OK
[TOOL] virustotal_scan called for file: suspicious_canbus.exe
[TOOL] Scan result: MALICIOUS — Threat: Trojan.CANBusHijack (47/72 engines flagged)
[AUTH] Agent agent-007 called virustotal_scan successfully

[AUTH] Validating token for tool: write_report... OK
[TOOL] Incident report saved to incident_report.json
[AUTH] Agent agent-007 called write_report successfully

[AGENT] Investigation complete. Status: SUCCESS
------------------------------------------------
Final Status: SUCCESS
```

---

## Quickstart

```bash
# 1. Clone the repo
git clone https://github.com/shreyas7ss/ZTF.git
cd ZTF

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the agent
python main.py
```

Requires **Python 3.12+**.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `langgraph` | Stateful agent graph execution |
| `langchain-core` | LangChain primitives used by LangGraph |
| `PyJWT` | JWT creation and RS256 signature verification |
| `cryptography` | RSA key pair generation |

---

## Roadmap

- **Phase 1 (current)** — Zero-Trust identity + auth layer with mock data
- **Phase 2** — OPA policy engine for fine-grained tool permissions + Redis token revocation
- **Phase 3** — Real VirusTotal / SIEM integration, Kafka event streaming, multi-agent coordination

---

## What Is Not Included (By Design)

- No real API keys or external network calls — everything is mocked
- No OPA, Redis, ML models, or Kafka (Phase 2/3 only)
- RSA keys are ephemeral (regenerated on each run) — use a KMS in production

---

*Built as Phase 1 of a Zero-Trust Agentic SOC research project.*

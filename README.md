# Zero-Trust Non-Human Identity Framework for Agentic SOC
### Data Security and Privacy — DS308

A Zero-Trust security harness that lets AI agents autonomously investigate SOC alerts while preventing privilege escalation, prompt injection, and rogue behavior — enforced through cryptographic identity, policy engines, real-time token revocation, and ML anomaly detection.

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![LangGraph](https://img.shields.io/badge/LangGraph-Enabled-orange?style=flat-square)
![OPA](https://img.shields.io/badge/OPA-Rego-lightblue?style=flat-square&logo=open-policy-agent)
![Redis](https://img.shields.io/badge/Redis-Revocation-red?style=flat-square&logo=redis)
![Groq](https://img.shields.io/badge/Groq-Llama_3.3-green?style=flat-square)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML_Supervisor-yellow?style=flat-square&logo=scikit-learn)
![License MIT](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

---

## Table of Contents
- [What This Project Does](#what-this-project-does)
- [Architecture Overview](#architecture-overview)
- [The 4 Security Layers](#the-4-security-layers)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [How to Run Each Demo](#how-to-run-each-demo)
- [Phase Breakdown](#phase-breakdown)
- [Demo Walkthrough](#demo-walkthrough)
- [The ML Model](#the-ml-model)
- [Agent Flow Diagrams](#agent-flow-diagrams)
- [Zero-Trust Principles Applied](#zero-trust-principles-applied)
- [Key Design Decisions](#key-design-decisions)
- [Known Limitations & Future Work](#known-limitations--future-work)
- [Tech Stack](#tech-stack)

---

## What This Project Does

In a modern Security Operations Center (SOC), AI agents are being deployed to handle high-volume alerts autonomously. However, these agents introduce a new attack surface: if an agent is compromised or prompt-injected, it could execute malicious shell commands, dump sensitive logs, or pivot into internal infrastructure.

This project solves that problem with a **Zero-Trust Security Harness**. The system treats every tool call as potentially malicious. Before an agent can read a log or scan a file, its request must pass through four distinct security gates — cryptographic identity, real-time revocation checks, centralized policy enforcement, and ML-based behavioral analysis.

The result: a compromised agent is blocked in **under 500ms** with no human intervention.

---

## Architecture Overview

```text
                                    ┌───────────────────────┐
                                    │    Security Alert     │
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │     Agent (LangGraph) │
                                    └───────────┬───────────┘
                                                │  Tool Call Attempt
                       ┌────────────────────────▼────────────────────────┐
                       │         Gate 1 — Identity Check (JWT)           │
                       │   RS256 signature valid? Token not expired?     │
                       └────────────────────────┬────────────────────────┘
                                                │ PASS
                       ┌────────────────────────▼────────────────────────┐
                       │         Gate 2 — Revocation Check (Redis)       │
                       │   Is this Token ID (JTI) still active?         │
                       └────────────────────────┬────────────────────────┘
                                                │ PASS
                       ┌────────────────────────▼────────────────────────┐
                       │         Gate 3 — Policy Check (OPA/Rego)        │
                       │   Does policy ALLOW this agent + tool?         │
                       └────────────────────────┬────────────────────────┘
                                                │ PASS
                       ┌────────────────────────▼────────────────────────┐
                       │         Gate 4 — Behavioral Check (ML)         │
                       │   Does session pattern match the baseline?     │
                       └───────────┬────────────────────────┬────────────┘
                                   │ NORMAL                 │ ANOMALY
                       ┌───────────▼───────────┐    ┌───────▼────────────┐
                       │     Tool Executes     │    │  Lockdown Trigger  │
                       │ (read_logs, vt_scan)  │    │ Revoke + Quarantine│
                       └───────────────────────┘    └────────────────────┘
```

---

## The 4 Security Layers

| Layer | Technology | What It Checks | What It Blocks | Response |
| :--- | :--- | :--- | :--- | :--- |
| **Gate 1 — Cryptographic ID** | RS256 JWT | Signature & Expiry | Forged/expired tokens | < 10ms |
| **Gate 2 — Real-time Revocation** | Redis | JTI blocklist status | Replay attacks, killed sessions | < 5ms |
| **Gate 3 — Policy Engine** | OPA (Rego) | RBAC & tool scopes | Unauthorized tool calls | < 50ms |
| **Gate 4 — ML Supervisor** | Isolation Forest | Session behavior patterns | Prompt injection, rogue behavior | < 100ms |

---

## Project Structure

```
ZTF/
├── core/                        # Shared security infrastructure (all phases use this)
│   ├── identity_provider.py     # JWT issuance & RS256 validation
│   ├── revocation_store.py      # Redis-backed token/agent revocation
│   ├── lockdown.py              # Auto-quarantine & incident logging
│   ├── opa_client.py            # OPA REST API client
│   ├── mock_data.py             # Simulated CAN bus logs & VirusTotal data
│   └── policies/
│       ├── soc_policy.rego      # OPA Rego policy (default deny)
│       └── upload_policy.py     # Uploads policy to running OPA server
│
├── security/                    # The 3 distinct gate-level wrappers
│   ├── tool_wrapper_p1.py       # Phase 1: Gate 1 only (JWT, no Docker needed)
│   ├── tool_wrapper_p2.py       # Phase 2/3: Gates 1, 2, 3 (JWT + Redis + OPA)
│   ├── tool_wrapper_p4.py       # Phase 4: All 4 gates (+ ML Supervisor)
│   └── soc_tools.py             # Tool factory (read_logs, virustotal_scan, etc.)
│
├── agents/                      # All agent implementations
│   ├── agent_p1.py              # Phase 1: Regex-based investigation
│   ├── agent_p3.py              # Phase 3+: Groq LLM-powered reasoning
│   ├── malicious_agent.py       # Gate 3 violator (exec_shell attempt)
│   └── malicious_agent_v2.py   # Gate 4 violator (behavioral attacker)
│
├── ml/                          # Machine Learning pipeline (Phase 4)
│   ├── telemetry.py             # JSONL event logger
│   ├── features.py              # 10-feature behavioral extractor
│   ├── generate_baseline.py     # Generates 100 normal training sessions
│   ├── train_model.py           # Trains & saves the Isolation Forest model
│   ├── ml_supervisor.py         # Real-time inference engine
│   └── models/
│       └── isolation_forest.pkl # Pre-trained model (ready to use)
│
├── llm/
│   └── llm_provider.py          # Groq Llama 3.3 70B initialization
│
├── demos/                       # Entry points — one per phase
│   ├── demo_p1.py               # Phase 1 demo (no Docker required)
│   ├── demo_p2.py               # Phase 2 demo (Docker required)
│   ├── demo_p3.py               # Phase 3 demo (Docker + Groq API)
│   └── demo_p4.py               # Phase 4 demo (Docker + Groq API + ML)
│
├── .env                         # API keys (not committed)
├── requirements.txt
└── README.md
```

---

## Setup & Installation

### Prerequisites
- **Python 3.12+**
- **Docker Desktop** (required for Phase 2, 3, and 4)
- **Groq API Key** — get one free at [console.groq.com](https://console.groq.com)

### Step 1 — Clone & Install

```bash
git clone https://github.com/shreyas7ss/ZTF.git
cd ZTF

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
```

### Step 2 — Configure API Key

Create a `.env` file in the project root:

```env
GROK_API_KEY=your_groq_api_key_here
```

### Step 3 — Start Docker Services

> **Only needed for Phase 2, 3, and 4. Skip for Phase 1.**

```bash
# If running for the first time:
docker run -d -p 6379:6379 --name redis-soc redis
docker run -d -p 8181:8181 --name opa-soc openpolicyagent/opa run --server --addr :8181

# If containers already exist (subsequent runs):
docker start redis-soc opa-soc
```

### Step 4 — Upload OPA Policy

> **Only needed for Phase 2, 3, and 4.**

```bash
python -m core.policies.upload_policy
```

Expected output: `[OPA] Policy uploaded successfully`

---

## How to Run Each Demo

All commands are run from the **project root** (`ZTF/`).

---

### Phase 1 — JWT Authentication Only
> No Docker required. Just Python.

```bash
python -m demos.demo_p1
```

**What you'll see:**
- Agent investigates alert for IP `192.168.1.45`
- JWT issued and validated on every tool call
- `incident_report.json` written with findings

---

### Phase 2 — Zero-Trust + Auto-Lockdown
> Requires: Docker (Redis + OPA)

```bash
docker start redis-soc opa-soc
python -m core.policies.upload_policy
python -m demos.demo_p2
```

**What you'll see:**
- `agent-007` successfully completes the investigation
- `agent-666` attempts `exec_shell` → **BLOCKED by OPA (Gate 3)**
- `[LOCKDOWN] TRIGGERED` appears in the terminal
- `lockdown_log.json` records the incident

---

### Phase 3 — LLM-Powered Intelligence
> Requires: Docker (Redis + OPA) + Groq API Key in `.env`

```bash
docker start redis-soc opa-soc
python -m core.policies.upload_policy
python -m demos.demo_p3
```

**What you'll see:**
- Agent receives a messy, unstructured alert
- Groq LLM extracts the IP and suspicious filename through reasoning
- LLM synthesises a professional incident verdict
- `incident_report.json` contains the full AI-generated analysis

---

### Phase 4 — Full 4-Gate Demo with ML Supervisor
> Requires: Docker (Redis + OPA) + Groq API Key in `.env`

```bash
docker start redis-soc opa-soc
python -m core.policies.upload_policy

# Train the behavioral model (run once, model is saved)
python -m ml.generate_baseline
python -m ml.train_model

# Run the full 3-scenario demo
python -m demos.demo_p4
```

**What you'll see (3 scenarios):**
1. `agent-007` — all 4 gates pass → **Investigation SUCCESS**
2. `agent-666` — tries `exec_shell` → **BLOCKED by Gate 3 (OPA)**
3. `agent-666-smart` — uses only allowed tools but hammers them 15x → **BLOCKED by Gate 4 (ML)**

**Output files:**
- `incident_report.json` — final investigation report
- `lockdown_log.json` — all lockdown incidents
- `telemetry_log.jsonl` — raw behavioral telemetry stream
- `ml/models/isolation_forest.pkl` — trained model artifact

---

## Phase Breakdown

### Phase 1: Secure Foundation
Builds the core investigation logic and the first layer of cryptographic defense.
- **Deliverables**: LangGraph agent workflow, JWT Identity Provider (RS256), `@requires_auth` decorator
- **The Wow Moment**: Calling a tool without a valid token fails instantly before a single line of tool logic runs

### Phase 2: Zero-Trust & Auto-Response
Introduces centralized policy enforcement and real-time incident response.
- **Deliverables**: Redis revocation store, OPA integration, `soc_policy.rego`, Lockdown Engine
- **The Wow Moment**: `agent-666` tries `exec_shell` and the terminal erupts with `[LOCKDOWN] TRIGGERED` as it gets quarantined

### Phase 3: LLM Intelligence
Upgrades the agent's reasoning using Groq's high-speed LLM inference.
- **Deliverables**: Groq Llama 3.3 70B integration, LLM entity extraction, Senior Analyst synthesis
- **The Wow Moment**: A messy, unstructured alert with no structured fields — the LLM correctly identifies the IP and suspicious file through language reasoning

### Phase 4: ML Behavioral Supervisor
Moves security from static rules (Gate 3) to dynamic behavioral analysis (Gate 4).
- **Deliverables**: Telemetry collector, feature engineering pipeline, Isolation Forest training, real-time inference
- **The Wow Moment**: `agent-666-smart` uses only permitted tools but gets caught because its pattern (15x `read_logs`) deviates from the trained baseline

---

## Demo Walkthrough

### Scenario A: Normal Agent
1. Alert received: *"Suspicious CAN bus activity on 192.168.1.45"*
2. JWT token issued and signed with RS256 private key
3. Each tool call passes all 4 gates
4. ML Supervisor scores the session as `NORMAL`
5. Final incident report saved — **Status: SUCCESS**

### Scenario B: Static Attacker (Gate 3)
1. `agent-666` obtains a token with minimal scope
2. Reads logs (legitimate) then attempts `exec_shell`
3. Gate 3 (OPA) denies it — tool not in policy allowlist
4. Lockdown fires: token revoked in Redis, agent quarantined
5. **Status: QUARANTINED**

### Scenario C: Smart Attacker (Gate 4)
1. `agent-666-smart` obtains a token and uses only allowed tools
2. Calls `read_logs` 15 times in rapid succession to scrape data
3. Gate 4 (ML Supervisor) detects anomalous call frequency & streak
4. Lockdown fires automatically — **Status: QUARANTINED**

---

## The ML Model

The ML Behavioral Supervisor uses a **self-trained Isolation Forest** — not a pretrained model.

| Property | Detail |
| :--- | :--- |
| **Algorithm** | Isolation Forest (`scikit-learn`) |
| **Training data** | 100 synthetic normal SOC sessions (generated by `ml/generate_baseline.py`) |
| **Features** | 10 behavioral dimensions per session |
| **Model file** | `ml/models/isolation_forest.pkl` |
| **Inference** | Real-time after every tool call |
| **Training time** | < 2 seconds |

**The 10 behavioral features:**

| # | Feature | What it captures |
| :-- | :--- | :--- |
| 1 | `total_calls` | Volume of tool calls |
| 2 | `distinct_tools_count` | Variety of tools used |
| 3 | `denied_calls_count` | Number of blocked attempts |
| 4 | `avg_time_between_calls` | Call pacing |
| 5 | `max_repeated_tool_streak` | Suspicious repetition |
| 6 | `read_logs_count` | Log read frequency |
| 7 | `virustotal_scan_count` | Scan frequency |
| 8 | `write_report_count` | Report write frequency |
| 9 | `session_duration` | Total session length |
| 10 | `deny_to_allow_ratio` | Ratio of denied vs allowed calls |

To retrain the model:
```bash
python -m ml.generate_baseline   # regenerate 100 normal sessions
python -m ml.train_model         # retrain and save the .pkl
```

---

## Agent Flow Diagrams

### Phase 1 — Linear Workflow
```
Start
  └─► request_token_node    (JWT issued)
        └─► read_logs_node   (Gate 1)
              └─► scan_file_node  (Gate 1)
                    └─► write_report_node  (Gate 1)
                          └─► success_node  ──► END
```

### Phase 4 — Supervised Workflow
```
Start
  └─► request_token_node
        └─► read_logs_node  ──[Gate 4]──► ANOMALY? ──► lockdown ──► END
                                  │
                                NORMAL
                                  │
              └─► scan_file_node  ──[Gate 4]──► ANOMALY? ──► lockdown ──► END
                                        │
                                      NORMAL
                                        │
                    └─► write_report_node ──► success_node ──► END
```

---

## Zero-Trust Principles Applied

| Principle | Implementation |
| :--- | :--- |
| **Continuous Verification** | Every tool call passes all active gates on every execution — no session exceptions |
| **Least Privilege** | Tokens are scoped to specific tools; OPA denies anything outside the explicit allowlist |
| **Assume Breach** | The ML Supervisor assumes the agent may be compromised and monitors behavioral drift |
| **Stateless Identity** | JWT verified cryptographically at the tool edge — no server-side sessions |
| **Fail Closed** | If Redis or OPA are unreachable, the system denies ALL access by default |

---

## Key Design Decisions

- **RS256 over HS256**: Asymmetric signing — tools verify tokens with the public key without ever accessing the private signing key.
- **OPA over if/else**: Security rules live in `soc_policy.rego`, not Python code. Policies can be updated without redeploying the agent.
- **Isolation Forest**: Ideal for anomaly detection where normal data is abundant but attacks are rare and unpredictable. No labeled attack data required.
- **Fail-Closed on Unreachable Services**: If Redis or OPA go offline, access is denied — security over availability.
- **Temperature = 0 for LLM**: Deterministic, reproducible outputs for security-critical reasoning.
- **Self-Trained ML**: The model is trained on synthetic data generated by the project itself — no external datasets needed.

---

## Known Limitations & Future Work

1. **Ephemeral Keys**: RSA keys generated in-process. *Future: AWS KMS / HashiCorp Vault.*
2. **Synthetic Training Data**: Model trained on simulated sessions. *Future: Train on real SOC telemetry.*
3. **Mock Logs Only**: No real SIEM connection. *Future: Splunk/Sentinel integration.*
4. **Single-Agent Scope**: One agent at a time. *Future: Multi-agent swarm coordination.*
5. **No Human Review Gate**: Lockdown is fully autonomous. *Future: Slack/Discord approval gates.*

---

## Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Agent Workflow** | LangGraph | Stateful graph-based agent execution |
| **Identity** | PyJWT + Cryptography | RS256 JWT issuance and validation |
| **Gate 2** | Redis | Real-time token and agent revocation |
| **Gate 3** | Open Policy Agent (OPA) | Rego-based external policy enforcement |
| **LLM Inference** | Groq / Llama 3.3 70B | High-speed reasoning and entity extraction |
| **ML Engine** | scikit-learn | Isolation Forest behavioral anomaly detection |
| **Data** | pandas | Feature matrix construction for ML training |

---

## Course Information
- **Course**: Data Security and Privacy — DS308
- **Project**: Zero-Trust Non-Human Identity Framework for Agentic SOC

---
*This project is submitted as the final capstone for DS308.*

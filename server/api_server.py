"""
api_server.py — FastAPI Backend for the Zero-Trust SOC Dashboard

Provides endpoints to:
    1. Start investigations using different agents/scenarios.
    2. Retrieve the status of an ongoing investigation.
    3. Serve security telemetry and incident logs.
    4. Provide ML behavioral scores for the dashboard charts.
"""

import uuid
import threading
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import our SOC logic
from agents.agent_p3 import run_agent as run_p3_agent
from agents.malicious_agent import run_malicious_agent
from agents.malicious_agent_v2 import run_malicious_agent_v2
from core.revocation_store import clear_stores, get_quarantine_list
from core.policies.upload_policy import upload_policy
import ml.telemetry as telemetry
import ml.ml_supervisor as ml_supervisor

app = FastAPI(title="Zero-Trust SOC API")

# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-Memory Session Store (Simplified for Demo)
# ---------------------------------------------------------------------------
# In a real app, this would be a database or Redis.
sessions: Dict[str, Dict[str, Any]] = {}

class InvestigationRequest(BaseModel):
    alert: str
    scenario: str  # "normal", "malicious_policy", "malicious_behavior"

# ---------------------------------------------------------------------------
# Investigation Runner
# ---------------------------------------------------------------------------

def run_investigation_task(session_id: str, alert: str, scenario: str):
    """Background task to execute the agent and update session state."""
    sessions[session_id]["status"] = "RUNNING"
    telemetry.set_session_id(session_id)
    
    try:
        if scenario == "normal":
            result = run_p3_agent(alert)
        elif scenario == "malicious_policy":
            result = run_malicious_agent(alert)
        elif scenario == "malicious_behavior":
            # Malicious v2 usually runs a loop, we'll wrap it to return a status
            run_malicious_agent_v2()
            result = "QUARANTINED"
        else:
            result = "UNKNOWN_SCENARIO"
        
        sessions[session_id]["final_status"] = result
        sessions[session_id]["status"] = "COMPLETED"
    except Exception as e:
        sessions[session_id]["status"] = "FAILED"
        sessions[session_id]["error"] = str(e)

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/investigate")
async def start_investigation(req: InvestigationRequest, background_tasks: BackgroundTasks):
    """Initialize a new investigation session."""
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "id": session_id,
        "alert": req.alert,
        "scenario": req.scenario,
        "status": "PENDING",
        "final_status": None,
        "error": None
    }
    background_tasks.add_task(run_investigation_task, session_id, req.alert, req.scenario)
    return {"session_id": session_id}

@app.get("/api/status/{session_id}")
async def get_status(session_id: str):
    """Retrieve the current state of an investigation."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get physical ML score if it's the current session
    current_score = 0.0
    if telemetry.current_session_id == session_id:
        current_score = ml_supervisor.get_behavior_score(session_id)
        
    return {**sessions[session_id], "ml_score": current_score}

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """Return high-level metrics for the dashboard."""
    # Count lockdowns from current file
    import json
    import os
    
    lockdown_count = 0
    if os.path.exists("lockdown_log.json"):
        try:
            with open("lockdown_log.json", "r") as f:
                logs = json.load(f)
                lockdown_count = len(logs)
        except: pass
        
    quarantined = get_quarantine_list()
    
    return {
        "total_investigations": len(sessions),
        "active_lockdowns": lockdown_count,
        "quarantined_agents": len(quarantined),
    }

@app.post("/api/system/reset")
async def reset_system():
    """Clear all logs and state for a fresh demo."""
    clear_stores()
    telemetry.clear_telemetry()
    upload_policy()
    sessions.clear()
    return {"message": "System reset successful"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

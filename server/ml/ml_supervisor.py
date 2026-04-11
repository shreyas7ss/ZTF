"""
ml_supervisor.py — Real-time Behavioral Inference Engine (Phase 4)

Loads the trained Isolation Forest model and scores sessions after each tool call.
If an anomaly is detected, it triggers the lockdown system automatically.
"""

import os
import joblib
import pandas as pd

from ml.features import extract_session_features
from core.lockdown import trigger_lockdown

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "isolation_forest.pkl")


class MLSupervisor:
    """Handles loading the anomaly detection model and scoring sessions."""

    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                print("[ML] Model loaded successfully.")
            except Exception as exc:
                print(f"[ML] Error loading model: {exc}")
        else:
            print("[ML] WARN: No model found. Behavioral detection is INACTIVE.")

    def score_session(self, session_id: str, agent_id: str) -> bool:
        """
        Evaluate current session behavior.
        Returns True if NORMAL, False if ANOMALOUS (triggers lockdown).
        """
        if not self.model:
            return True  # Fail open if no model trained yet

        features = extract_session_features(session_id)
        df = pd.DataFrame([features])
        prediction = self.model.predict(df)[0]  # 1 = normal, -1 = anomaly

        if prediction == -1:
            print(f"[ML] !!! ANOMALY DETECTED for session {session_id} (Agent: {agent_id})")
            trigger_lockdown(
                agent_id=agent_id,
                jti="session-level-lockdown",
                reason=f"ML Behavioral Anomaly Detected — Features: {features}",
            )
            return False

        return True


# Global supervisor singleton — loaded once at module import time
supervisor = MLSupervisor()


def check_behavior(session_id: str, agent_id: str) -> bool:
    """Public interface to score a session against the behavioral baseline."""
    return supervisor.score_session(session_id, agent_id)


def get_behavior_score(session_id: str) -> float:
    """Returns a raw anomaly score (0.0 to 1.0). Higher = more anomalous."""
    if not supervisor.model:
        return 0.0
    
    try:
        features = extract_session_features(session_id)
        df = pd.DataFrame([features])
        # decision_function returns negative values for anomalies.
        # We transform it into a 0-1 range where > 0.5 is suspicious.
        raw_score = supervisor.model.decision_function(df)[0]
        # Map roughly: normal (0.1) -> 0.1, anomaly (-0.1) -> 0.8
        normalized = 0.5 - (raw_score * 2) 
        return max(0.0, min(1.0, normalized))
    except:
        return 0.0

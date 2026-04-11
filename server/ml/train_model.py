"""
train_model.py — Isolation Forest Trainer for SOC Behavioral Analysis

Loads the baseline telemetry, extracts 10-D features per session,
trains an Isolation Forest, and saves the binary model to ml/models/.

Run from project root:
    python -m ml.train_model
"""

import os
import json
import sys
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml.features import extract_session_features

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
TELEMETRY_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "telemetry_log.jsonl"
)


def main():
    print("[TRAIN] Starting model training pipeline...")

    if not os.path.exists(TELEMETRY_LOG_PATH):
        print("[ERROR] No telemetry log found. Run 'python -m ml.generate_baseline' first.")
        return

    # Identify all unique sessions
    sessions = set()
    with open(TELEMETRY_LOG_PATH, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
                sessions.add(event["session_id"])
            except Exception:
                continue

    print(f"[TRAIN] Found {len(sessions)} sessions in logs.")

    # Extract features for each session
    data = [extract_session_features(sid) for sid in sessions]
    df = pd.DataFrame(data)
    print(f"[TRAIN] Feature matrix shape: {df.shape}")

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,  # Assume ~1% of baseline may be noisy
        random_state=42,
    )
    print("[TRAIN] Fitting Isolation Forest model...")
    model.fit(df)

    # Save model
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[TRAIN] Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()

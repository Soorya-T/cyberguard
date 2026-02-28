"""
CyberGuard - Pod B
Machine Learning Training Script (Logistic Regression)

Purpose:
---------
Trains the deterministic ML booster model used by Pod B.
This model does NOT replace heuristic scoring.
It only provides a probabilistic risk boost.

Architecture Compliance:
-------------------------
- Deterministic model
- No runtime retraining
- Versioned model export
- Portable path resolution
- No hardcoded absolute paths
"""

from pathlib import Path
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression


# -------------------------------------------------
# FEATURE ORDER CONTRACT
# MUST MATCH FeatureBuilder.FEATURE_ORDER EXACTLY
# -------------------------------------------------
#
# [
#   domain_spoof,
#   reply_mismatch,
#   attachment_risk,
#   urgency_detected,
#   link_obfuscation,
#   signal_count,
#   high_severity_count
# ]
#
# Changing order WILL break inference determinism.
# -------------------------------------------------


def build_training_data():
    """
    Builds a minimal deterministic dataset for MVP.

    NOTE:
    This is placeholder synthetic data for initial model bootstrapping.
    Replace with real phishing dataset in production.
    """

    X = np.array([
        [1, 1, 1, 1, 1, 5, 3],  # Strong phishing
        [1, 0, 1, 1, 0, 3, 2],  # Phishing
        [0, 1, 0, 1, 0, 2, 1],  # Suspicious
        [0, 0, 0, 0, 0, 0, 0],  # Safe
        [0, 0, 0, 1, 0, 1, 0],  # Mild suspicious
        [0, 0, 0, 0, 0, 1, 0],  # Safe
    ])

    y = np.array([
        1,  # phishing
        1,
        1,
        0,  # safe
        0,
        0,
    ])

    return X, y


def train_model():
    """
    Train deterministic Logistic Regression model.
    """

    X, y = build_training_data()

    model = LogisticRegression(
        max_iter=1000,        # Prevent convergence warnings
        solver="lbfgs",       # Stable solver
        random_state=42       # Deterministic reproducibility
    )

    model.fit(X, y)

    return model


def save_model(model):
    """
    Saves model inside current ML directory.
    """

    BASE_DIR = Path(__file__).resolve().parent

    MODEL_PATH = BASE_DIR / "phishing_model_v1.pkl"

    joblib.dump(model, MODEL_PATH)

    return MODEL_PATH


if __name__ == "__main__":
    print("\n🚀 Training CyberGuard Pod B ML Booster...\n")

    model = train_model()

    model_path = save_model(model)

    print("✅ Model trained successfully")
    print("📁 Saved to:", model_path)
    print("🔢 Feature count:", model.n_features_in_)
    print("🎯 Classes:", model.classes_)
    print("\nDone.\n")
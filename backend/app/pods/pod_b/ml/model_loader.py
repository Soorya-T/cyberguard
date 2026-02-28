import os
import joblib


def load_model():
    base_dir = os.path.dirname(__file__)
    model_path = os.path.join(base_dir, "phishing_model_v1.pkl")

    if not os.path.exists(model_path):
        return None

    return joblib.load(model_path)
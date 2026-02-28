"""
ML Booster Layer (Logistic Regression)

Implements:
- Deterministic feature validation
- Safe probability inference
- Controlled boost mapping
- Hard ML boundaries (never overrides deterministic signals)

This module strictly enforces:
- Feature shape integrity
- Deterministic execution
- Safe fallback behavior
"""

from typing import List, Tuple
from app.pods.pod_b.ml.model_loader import load_model


class MLBooster:
    """
    Machine Learning Boost Layer.

    ML enhances deterministic scoring.
    It NEVER overrides strong deterministic verdicts.

    This class enforces strict feature validation to prevent:
    - Shape mismatches
    - Silent model corruption
    - Non-deterministic execution
    """

    def __init__(self):
        self.model = load_model()
        self.model_loaded = self.model is not None

        if self.model_loaded:
            self.expected_features = self.model.n_features_in_
        else:
            self.expected_features = 0

    def get_boost(self, feature_vector: List[float]) -> Tuple[int, float]:
        """
        Returns:
        - boost score (int)
        - probability confidence (float)

        Safe behavior:
        - If model missing → neutral output
        - If feature mismatch → fail safe (no boost)
        - If inference error → fail safe
        """

        # Graceful fallback if model not loaded
        if not self.model_loaded:
            return 0, 0.5

        # 🔒 Strict feature length enforcement
        if len(feature_vector) != self.expected_features:
            # Hard fail-safe: no ML boost
            # Prevents scoring engine crash
            return 0, 0.5

        try:
            probability = float(
                self.model.predict_proba([feature_vector])[0][1]
            )

        except Exception:
            # Any inference failure → safe fallback
            return 0, 0.5

        boost = self._probability_to_boost(probability)

        return boost, round(probability, 2)

    def _probability_to_boost(self, probability: float) -> int:
        """
        Controlled boost mapping.

        Prevents ML from dominating deterministic logic.
        Converts probability into bounded additive score.
        """

        if probability < 0.40:
            return 0
        elif probability < 0.60:
            return 10
        elif probability < 0.80:
            return 20
        else:
            return 30
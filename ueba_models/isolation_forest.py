"""
ueba_models/isolation_forest.py
────────────────────────────────
Layer 1 — Isolation Forest inference wrapper.

Loads the trained model + scaler from disk once on startup.
At runtime: call score(vec) for every incoming enriched log.
Microsecond latency — safe for 1.1M logs/day streaming.
"""

import logging
import numpy as np
import joblib
from pathlib import Path

log = logging.getLogger("ueba.if")


def _zero_variance_cols(scaler, tag: str) -> np.ndarray:
    """Indices of features that were CONSTANT (zero-variance) in training.

    See ueba_models/autoencoder.py for the full rationale: StandardScaler leaves
    such columns unscaled (scale_=1.0), so a value the live feed starts
    populating after training passes through unnormalised. These columns carry
    no learned signal, so we zero them post-scale. Remove once retrained on
    representative data.
    """
    var = getattr(scaler, "var_", None)
    if var is None:
        return np.array([], dtype=int)
    cols = np.where(var == 0)[0]
    if len(cols):
        log.warning("%s skew-guard: masking %d zero-variance feature(s) the "
                    "model never learned (indices %s)", tag, len(cols), list(cols))
    return cols


class IsolationForestScorer:
    """
    Wraps the trained Isolation Forest for real-time inference.

    Isolation Forest scores:
      Closer to  0.0  →  normal
      Closer to -1.0  →  highly anomalous

    We convert to a 0-1 anomaly score where 1 = most anomalous.
    """

    def __init__(self, model_path: str, scaler_path: str, config: dict):
        self.config = config["isolation_forest"]
        self.thresholds = config["isolation_forest"]["thresholds"]

        # Load model and scaler from disk
        if not Path(model_path).exists():
            raise FileNotFoundError(
                f"Isolation Forest model not found: {model_path}\n"
                f"Run ueba_trainer.py first."
            )
        if not Path(scaler_path).exists():
            raise FileNotFoundError(
                f"Scaler not found: {scaler_path}\n"
                f"Run ueba_trainer.py first."
            )

        self.model  = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self._dead_cols = _zero_variance_cols(self.scaler, "IF")
        log.info("Isolation Forest loaded from %s", model_path)

    def score(self, feature_vec: np.ndarray) -> dict:
        """
        Score a single feature vector.

        Args:
            feature_vec: numpy array of shape (35,)

        Returns:
            dict with:
              raw_score    — Isolation Forest raw score (-1 to 0 range)
              anomaly_score — normalized 0-1 (1 = most anomalous)
              verdict      — 'normal' | 'suspicious' | 'anomalous' | 'highly_anomalous'
              is_anomalous — bool (True if should be flagged)
        """
        # Scale the feature vector
        vec_scaled = self.scaler.transform(
            feature_vec.reshape(1, -1)
        ).astype(np.float32)
        if len(self._dead_cols):
            vec_scaled[:, self._dead_cols] = 0.0

        # Raw score — more negative = more anomalous
        raw_score = float(self.model.score_samples(vec_scaled)[0])

        # Convert to 0-1 anomaly score
        # Isolation Forest scores typically range from -0.5 to 0.5
        # We clip and normalize: -0.5 → 1.0 (most anomalous), 0.5 → 0.0 (normal)
        anomaly_score = float(np.clip((-raw_score - 0.0) / 0.5, 0.0, 1.0))

        # Verdict based on raw score thresholds from config
        if raw_score <= self.thresholds["highly_anomalous"]:
            verdict = "highly_anomalous"
            is_anomalous = True
        elif raw_score <= self.thresholds["anomalous"]:
            verdict = "anomalous"
            is_anomalous = True
        elif raw_score <= self.thresholds["suspicious"]:
            verdict = "suspicious"
            is_anomalous = True
        else:
            verdict = "normal"
            is_anomalous = False

        return {
            "raw_score":     raw_score,
            "anomaly_score": anomaly_score,
            "verdict":       verdict,
            "is_anomalous":  is_anomalous,
        }

    def score_batch(self, feature_matrix: np.ndarray) -> list[dict]:
        """
        Score a batch of feature vectors.
        More efficient than calling score() in a loop.
        feature_matrix: shape (N, 35)
        """
        scaled = self.scaler.transform(feature_matrix).astype(np.float32)
        if len(self._dead_cols):
            scaled[:, self._dead_cols] = 0.0
        raw_scores = self.model.score_samples(scaled)

        results = []
        for raw_score in raw_scores:
            raw_score = float(raw_score)
            anomaly_score = float(np.clip(-raw_score / 0.5, 0.0, 1.0))

            if raw_score <= self.thresholds["highly_anomalous"]:
                verdict, is_anomalous = "highly_anomalous", True
            elif raw_score <= self.thresholds["anomalous"]:
                verdict, is_anomalous = "anomalous", True
            elif raw_score <= self.thresholds["suspicious"]:
                verdict, is_anomalous = "suspicious", True
            else:
                verdict, is_anomalous = "normal", False

            results.append({
                "raw_score":     raw_score,
                "anomaly_score": anomaly_score,
                "verdict":       verdict,
                "is_anomalous":  is_anomalous,
            })
        return results

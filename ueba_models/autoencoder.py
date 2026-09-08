"""
ueba_models/autoencoder.py
───────────────────────────
Layer 2 — Autoencoder inference wrapper.

Loads per-user models lazily (on first encounter).
Falls back to global model for unknown/rare users.
Uses LRU cache to keep only the most recently used models in memory.
"""

import json
import logging
from collections import OrderedDict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

log = logging.getLogger("ueba.autoencoder")


# ── Train/serve skew guard ────────────────────────────────────────────────────

def _zero_variance_cols(scaler, tag: str) -> np.ndarray:
    """Indices of features that were CONSTANT in the training set.

    StandardScaler stores scale_=1.0 (var_=0) for a zero-variance column, so it
    does not normalise it. If the live feed later starts populating that field
    (e.g. an upstream enricher adds host_5m / rule.level AFTER the model was
    trained), the raw value passes through unscaled and detonates the
    autoencoder reconstruction error — pinning every event to highly_anomalous.
    Such columns carry no learned signal anyway (the model trained on a
    constant), so callers zero them post-scale to keep the model on the
    distribution it was actually trained on. Remove once the model is retrained
    on representative data (the scaler will then have real variance here).
    """
    var = getattr(scaler, "var_", None)
    if var is None:
        return np.array([], dtype=int)
    cols = np.where(var == 0)[0]
    if len(cols):
        log.warning("%s skew-guard: masking %d zero-variance feature(s) the "
                    "model never learned (indices %s)", tag, len(cols), list(cols))
    return cols


# ── Autoencoder Architecture (must match ueba_trainer.py) ─────────────────────

class Autoencoder(nn.Module):
    def __init__(self, input_dim: int = 35,
                 hidden_dims: list[int] | None = None,
                 dropout: float = 0.1):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [24, 12]

        encoder_layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev_dim = h_dim
        self.encoder = nn.Sequential(*encoder_layers)

        decoder_layers = []
        for h_dim in reversed(hidden_dims[:-1]):
            decoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev_dim = h_dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> float:
        with torch.no_grad():
            recon = self.forward(x)
            return float(torch.mean((x - recon) ** 2).item())


# ── Autoencoder Scorer ────────────────────────────────────────────────────────

class AutoencoderScorer:
    """
    Manages per-user and global autoencoders for real-time inference.

    Design:
    - Models are loaded lazily (only when that user is seen)
    - LRU cache keeps max_loaded_models in RAM
    - Falls back to global model when user model doesn't exist
    - Uses GPU (CUDA) for inference when available
    """

    def __init__(self, autoencoder_dir: str, scaler,
                 thresholds_path: str, config: dict):
        self.ae_dir     = Path(autoencoder_dir)
        self.scaler     = scaler
        self._dead_cols = _zero_variance_cols(scaler, "AE")
        self.ae_config  = config["autoencoder"]
        self.arch_cfg   = self.ae_config["architecture"]
        self.max_cached = config["streaming"]["max_loaded_user_models"]

        # `inference_device` overrides `device` for streaming inference only,
        # so the trainer keeps using GPU while the engine can run on CPU.
        # Tiny per-user AEs (~3K params) are memory-bound on GPU and pinning
        # them there starves co-tenant GPU workloads (ollama, etc.).
        dev_name = self.ae_config.get("inference_device") \
                   or self.ae_config.get("device", "cuda")
        if dev_name == "cuda" and torch.cuda.is_available():
            self.device = torch.device("cuda")
            log.info("Autoencoder inference on GPU: %s", torch.cuda.get_device_name(0))
        else:
            self.device = torch.device("cpu")
            log.info("Autoencoder inference on CPU")

        # Load anomaly thresholds for each user model
        if not Path(thresholds_path).exists():
            raise FileNotFoundError(
                f"Thresholds file not found: {thresholds_path}\n"
                f"Run ueba_trainer.py first."
            )
        with open(thresholds_path) as f:
            self.thresholds: dict[str, float] = json.load(f)

        # LRU cache: {username: model}
        self._cache: OrderedDict[str, Autoencoder] = OrderedDict()

        # Load global model at startup (always needed as fallback)
        self.global_model = self._load_model("global")
        if self.global_model is None:
            raise FileNotFoundError(
                f"Global autoencoder not found in {self.ae_dir}\n"
                f"Run ueba_trainer.py first."
            )
        log.info("Global autoencoder loaded from %s", self.ae_dir / "global.pt")

    def _load_model(self, username: str) -> Autoencoder | None:
        """Load autoencoder weights from disk for a specific user."""
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                            for c in username)
        model_path = self.ae_dir / f"{safe_name}.pt"

        if not model_path.exists():
            return None

        model = Autoencoder(
            input_dim=self.arch_cfg["input_dim"],
            hidden_dims=self.arch_cfg["hidden_dims"],
            dropout=0.0,    # disable dropout at inference
        ).to(self.device)
        model.load_state_dict(
            torch.load(str(model_path), map_location=self.device)
        )
        model.eval()
        return model

    def _get_model(self, username: str) -> tuple[Autoencoder, str]:
        """
        Get the best available model for a user.
        Returns (model, model_name_used).
        Manages LRU cache automatically.
        """
        # Check cache first
        if username in self._cache:
            self._cache.move_to_end(username)   # mark as recently used
            return self._cache[username], username

        # Try to load from disk
        model = self._load_model(username)
        if model is not None:
            # Add to cache, evict oldest if needed
            if len(self._cache) >= self.max_cached:
                evicted = next(iter(self._cache))
                del self._cache[evicted]
                log.debug("LRU evicted model for user: %s", evicted)
            self._cache[username] = model
            log.debug("Loaded model for user: %s", username)
            return model, username

        # Fall back to global model
        return self.global_model, "global"

    def score(self, feature_vec: np.ndarray, username: str) -> dict:
        """
        Compute behavioral anomaly score for one feature vector.

        Args:
            feature_vec: numpy array shape (35,)
            username:    the user associated with this log event

        Returns dict with:
            reconstruction_error  — raw MSE
            deviation_score       — normalized 0-1 (1 = most anomalous)
            threshold             — threshold used for this user
            is_anomalous          — bool
            model_used            — 'global' or username
        """
        # Scale feature vector
        vec_scaled = self.scaler.transform(
            feature_vec.reshape(1, -1)
        ).astype(np.float32)
        # Neutralise features the model never learned (see _zero_variance_cols).
        if len(self._dead_cols):
            vec_scaled[:, self._dead_cols] = 0.0
        tensor = torch.from_numpy(vec_scaled).to(self.device)

        # Get best model for this user
        model, model_used = self._get_model(username)

        # Compute reconstruction error
        recon_error = model.reconstruction_error(tensor)

        # Get threshold for this user (fall back to global threshold)
        threshold = self.thresholds.get(
            username,
            self.thresholds.get("global", 0.1)
        )

        # Normalize deviation score to 0-1
        # At threshold: score = 0.5
        # At 2x threshold: score ≈ 0.75 etc.
        # This gives smooth gradient rather than hard 0/1
        deviation_score = float(
            np.clip(recon_error / (2.0 * threshold + 1e-8), 0.0, 1.0)
        )
        is_anomalous = recon_error > threshold

        return {
            "reconstruction_error": float(recon_error),
            "deviation_score":      deviation_score,
            "threshold":            float(threshold),
            "is_anomalous":         is_anomalous,
            "model_used":           model_used,
        }

    @property
    def cache_size(self) -> int:
        return len(self._cache)

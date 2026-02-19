"""
analyzer.py — SENTINEL AI Engine (Isolation Forest Pipeline)
=============================================================
Pipeline:
  Wazuh Indexer
    → Noise Filter        (feature_builder)
    → Feature Extraction  (feature_builder)
    → Isolation Forest    (sklearn)
    → Risk Classification
    → Global Risk
    → ai_risks.json

State machine:
  LEARNING  – first WARMUP_CYCLES cycles: collect data, no scoring
  OK        – normal operation
  DEGRADED  – Indexer unreachable, last good state preserved + retried
"""

from __future__ import annotations

import json
import logging
import os
import time
import warnings
from copy import deepcopy
from datetime import datetime, timezone

import joblib
import numpy as np
from opensearchpy import OpenSearch
from sklearn.ensemble import IsolationForest

import feature_builder
from feature_builder import FEATURE_NAMES, N_FEATURES, zero_vector_entry

# ── SSL noise suppression ─────────────────────────────────────────────────────
warnings.filterwarnings("ignore")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [AI ENGINE] - %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
INDEXER_HOST  = os.getenv("INDEXER_HOST", "wazuh.indexer")
INDEXER_PORT  = int(os.getenv("INDEXER_PORT", "9200"))
IDX_USER      = os.getenv("INDEXER_USER", "admin")
IDX_PASS      = os.getenv("INDEXER_PASS", "SecretPassword")

OUTPUT_FILE   = "/shared_data/ai_risks.json"
MODEL_FILE    = "/shared_data/model.pkl"

SCAN_INTERVAL  = 30    # seconds between normal scans
FEATURE_WINDOW = 5     # minutes of history per scan
WARMUP_CYCLES  = 3     # cycles before first scoring
OFFLINE_RETRY  = 10    # seconds between offline retries
BOOT_DELAY     = 20    # seconds to wait for Indexer on first start
CONTAMINATION  = 0.1   # IsolationForest anomaly fraction
MIN_SAMPLES    = 4     # minimum vectors needed to train (avoids sklearn crash)
MAX_HISTORY    = 500   # cap history size to avoid unbounded memory growth

# ── Risk thresholds ───────────────────────────────────────────────────────────
RISK_THRESHOLDS = [
    (0.8, "CRITICAL"),
    (0.6, "HIGH"),
    (0.4, "MEDIUM"),
    (0.0, "LOW"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": INDEXER_HOST, "port": INDEXER_PORT}],
        http_compress=True,
        http_auth=(IDX_USER, IDX_PASS),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
    )


def classify_risk(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def normalise_score(raw: float) -> float:
    """
    Map IsolationForest decision_function → [0.0, 1.0].
    decision_function: positive = normal, negative = anomalous.
    We flip+shift so that 0 = normal, 1 = very anomalous.
    """
    return float(np.clip(-raw + 0.5, 0.0, 1.0))


def dominant_feature(feature_vector: list[int], baseline: np.ndarray) -> str:
    """Feature with the largest positive deviation from the training mean."""
    vec        = np.array(feature_vector, dtype=float)
    deviations = vec - baseline
    idx        = int(np.argmax(deviations))
    return FEATURE_NAMES[idx]


def write_output(payload: dict) -> None:
    """Atomic write to ai_risks.json via a tmp file."""
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    tmp = OUTPUT_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, OUTPUT_FILE)
        logger.info("ai_risks.json updated — status: %s", payload.get("status"))
    except Exception as exc:
        logger.error("write_output failed: %s", exc)


def load_model() -> IsolationForest | None:
    if os.path.exists(MODEL_FILE):
        try:
            m = joblib.load(MODEL_FILE)
            logger.info("Loaded persisted model from %s", MODEL_FILE)
            return m
        except Exception as exc:
            logger.warning("Could not load model (%s) — will retrain.", exc)
    return None


def save_model(model: IsolationForest) -> None:
    try:
        os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
        joblib.dump(model, MODEL_FILE)
        logger.info("Model persisted to %s", MODEL_FILE)
    except Exception as exc:
        logger.warning("Could not save model: %s", exc)


def train_model(X: np.ndarray) -> IsolationForest:
    """Fit a fresh IsolationForest on X and persist it."""
    model = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=100,
        random_state=42,
    )
    model.fit(X)
    save_model(model)
    logger.info("Model trained on %d vectors.", len(X))
    return model


# ── Main engine loop ──────────────────────────────────────────────────────────

def run_engine() -> None:
    cycle             = 0
    history: list[list[int]] = []
    model: IsolationForest | None = load_model()
    baseline: np.ndarray | None   = None
    last_good_output: dict | None = None

    logger.info("AI Engine online — boot delay %ds.", BOOT_DELAY)
    time.sleep(BOOT_DELAY)

    while True:
        try:
            # ── 1. Connect ────────────────────────────────────────────────────
            client = get_client()
            if not client.ping():
                raise ConnectionError("Indexer ping failed")

            # ── 2. Feature extraction ─────────────────────────────────────────
            agent_features = feature_builder.build_features(client, FEATURE_WINDOW)

            if not agent_features:
                # No recent alerts — use zero vectors for known agents
                known          = feature_builder.discover_agents(client)
                agent_features = [zero_vector_entry(a) for a in known]
                if not agent_features:
                    logger.info("No agents found — skipping cycle.")
                    time.sleep(SCAN_INTERVAL)
                    continue

            # Add current vectors to rolling history
            new_vectors = [af["feature_vector"] for af in agent_features]
            history.extend(new_vectors)

            # Hard cap to avoid unbounded memory growth
            if len(history) > MAX_HISTORY:
                history = history[-MAX_HISTORY:]

            cycle += 1
            logger.info(
                "Cycle %d | agents=%d | history=%d vectors",
                cycle, len(agent_features), len(history),
            )

            # ── 3. LEARNING phase ─────────────────────────────────────────────
            if cycle <= WARMUP_CYCLES:
                write_output({
                    "timestamp":   utc_now(),
                    "status":      "LEARNING",
                    "global_risk": None,
                    "agents":      [],
                    "message":     f"Collecting baseline ({cycle}/{WARMUP_CYCLES} cycles).",
                })
                time.sleep(SCAN_INTERVAL)
                continue

            # ── 4. Need minimum samples to train? ─────────────────────────────
            if len(history) < MIN_SAMPLES:
                logger.info("Not enough samples (%d < %d) — waiting.", len(history), MIN_SAMPLES)
                time.sleep(SCAN_INTERVAL)
                continue

            # ── 5. Train / retrain ────────────────────────────────────────────
            X = np.array(history, dtype=float)

            need_train = (model is None) or (cycle % 10 == 4)  # retrain every 10 cycles
            if need_train:
                model    = train_model(X)
                baseline = X.mean(axis=0)
            elif baseline is None:
                baseline = X.mean(axis=0)

            # ── 6. Score current agents ───────────────────────────────────────
            current_X  = np.array(new_vectors, dtype=float)
            raw_scores = model.decision_function(current_X)

            scored_agents = []
            for i, af in enumerate(agent_features):
                score = normalise_score(float(raw_scores[i]))
                risk  = classify_risk(score)
                dom   = dominant_feature(af["feature_vector"], baseline)
                scored_agents.append({
                    "agent":            af["agent"],
                    "score":            round(score, 4),
                    "risk":             risk,
                    "dominant_feature": dom,
                    "features":         af["features"],
                })

            # ── 7. Global risk ────────────────────────────────────────────────
            global_risk = round(float(np.mean([a["score"] for a in scored_agents])), 4)

            payload = {
                "timestamp":   utc_now(),
                "status":      "OK",
                "global_risk": global_risk,
                "agents":      scored_agents,
            }
            last_good_output = deepcopy(payload)
            write_output(payload)

        except Exception as exc:
            logger.error("Engine error: %s", exc, exc_info=True)

            # ── DEGRADED: preserve last good state ────────────────────────────
            degraded = deepcopy(last_good_output) if last_good_output else {
                "global_risk": None,
                "agents":      [],
            }
            degraded.update({
                "timestamp": utc_now(),
                "status":    "DEGRADED",
                "message":   f"Cannot reach Indexer — last known state preserved. ({exc})",
            })
            write_output(degraded)

            logger.info("Retrying in %ds...", OFFLINE_RETRY)
            time.sleep(OFFLINE_RETRY)
            continue

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run_engine()

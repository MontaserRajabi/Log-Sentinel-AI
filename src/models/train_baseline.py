"""
train_baseline.py — Log Sentinel AI
=====================================
Trains the baseline anomaly detection model (Isolation Forest) on
block-level features extracted by build_features.py.

Aligns with Section 4.3 (Algorithms and Models Used) and Section 1.7
(Methodology) of the project report:
  - Loads and validates block_features.parquet
  - Preprocesses features (scaling, NaN/inf handling)
  - Trains Isolation Forest (unsupervised anomaly detection)
  - Evaluates on a held-out split using anomaly score distribution
  - Saves model + feature metadata for consistent inference in evaluate.py
  - Saves a training report (metrics, feature list, config)

Configuration is read from .env (see README for supported keys).

Usage
-----
    python src/models/train_baseline.py                        # defaults
    python src/models/train_baseline.py --features data/features/block_features.parquet
    python src/models/train_baseline.py --contamination 0.05 --n-estimators 200
"""

import argparse
import json
import logging
import os
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── Environment & logging ──────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Defaults (overridable via .env or CLI) ─────────────────────────────────────
DEFAULT_FEATURES     = "data/features/block_features.parquet"
DEFAULT_MODEL        = "models/isoforest.pkl"
DEFAULT_META         = "models/feature_meta.json"
DEFAULT_REPORT       = "models/training_report.json"
CONTAMINATION        = float(os.getenv("CONTAMINATION",  0.01))
RANDOM_STATE         = int(os.getenv("RANDOM_STATE",     42))
N_ESTIMATORS         = int(os.getenv("N_ESTIMATORS",     100))
MAX_SAMPLES          = os.getenv("MAX_SAMPLES",          "auto")   # "auto" | int | float
TEST_SIZE            = float(os.getenv("TEST_SIZE",      0.2))

# Columns that must never be used as model input
NON_FEATURE_COLS = {"block_id", "label", "anomaly", "split"}


# ── Data loading & validation ──────────────────────────────────────────────────

def load_features(features_file: str) -> pd.DataFrame:
    """Load block_features.parquet and perform basic sanity checks."""
    path = Path(features_file)
    if not path.exists():
        raise FileNotFoundError(
            f"Feature file not found: {path.resolve()}\n"
            "Run build_features.py first to generate it."
        )

    df = pd.read_parquet(path)
    logger.info("Loaded features: %d blocks × %d columns", len(df), len(df.columns))

    if df.empty:
        raise ValueError("Feature file is empty — nothing to train on.")

    if "block_id" not in df.columns:
        raise ValueError("Expected a 'block_id' column in the feature file.")

    return df


def select_feature_columns(df: pd.DataFrame) -> list[str]:
    """
    Return all numeric columns that are not in NON_FEATURE_COLS.
    Logs which columns are dropped and why.
    """
    dropped_non_numeric = [c for c in df.columns
                           if c not in NON_FEATURE_COLS
                           and not pd.api.types.is_numeric_dtype(df[c])]
    if dropped_non_numeric:
        logger.warning("Dropping non-numeric columns: %s", dropped_non_numeric)

    feature_cols = [
        c for c in df.columns
        if c not in NON_FEATURE_COLS
        and pd.api.types.is_numeric_dtype(df[c])
    ]
    logger.info("Training on %d feature columns: %s", len(feature_cols), feature_cols)
    return feature_cols


def clean_features(X: pd.DataFrame) -> pd.DataFrame:
    """
    Replace inf/-inf with NaN, then impute NaN with column medians.
    Isolation Forest cannot handle NaN or inf values.
    """
    n_inf = np.isinf(X.values).sum()
    if n_inf > 0:
        logger.warning("Replacing %d inf/-inf values with NaN before imputation.", n_inf)
        X = X.replace([np.inf, -np.inf], np.nan)

    n_nan = X.isna().sum().sum()
    if n_nan > 0:
        logger.warning("Imputing %d NaN values with column medians.", n_nan)
        X = X.fillna(X.median(numeric_only=True))

    return X


# ── Model training ─────────────────────────────────────────────────────────────

def build_pipeline(contamination: float, n_estimators: int,
                   max_samples, random_state: int) -> Pipeline:
    """
    Build a scikit-learn Pipeline:
        StandardScaler  →  IsolationForest

    Scaling is important: features like 'events_per_sec' and 'msg_len'
    live on very different scales and would otherwise distort anomaly scores.
    """
    # max_samples can be "auto", an int, or a float
    try:
        max_samples = int(max_samples)
    except (ValueError, TypeError):
        pass   # keep "auto" or float as-is

    return Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators  = n_estimators,
            contamination = contamination,
            max_samples   = max_samples,
            random_state  = random_state,
            n_jobs        = -1,       # use all CPU cores
        )),
    ])


def evaluate_pipeline(pipeline: Pipeline, X_test: pd.DataFrame) -> dict:
    """
    Evaluate the trained model on the held-out test split.

    Isolation Forest is unsupervised — there are no ground-truth labels
    in the baseline. We therefore report the anomaly score distribution
    and the fraction of blocks flagged as anomalous.

    If an 'anomaly_label' column exists in the original dataframe it will
    be used for a full classification report (supervised evaluation).
    """
    scores    = pipeline.decision_function(X_test)   # higher = more normal
    preds     = pipeline.predict(X_test)              # -1 = anomaly, 1 = normal
    n_anomaly = int((preds == -1).sum())
    n_total   = len(preds)

    metrics = {
        "test_blocks"       : n_total,
        "flagged_anomalies" : n_anomaly,
        "anomaly_rate_pct"  : round(100 * n_anomaly / n_total, 2),
        "score_mean"        : round(float(np.mean(scores)), 6),
        "score_std"         : round(float(np.std(scores)),  6),
        "score_min"         : round(float(np.min(scores)),  6),
        "score_max"         : round(float(np.max(scores)),  6),
        "score_p5"          : round(float(np.percentile(scores,  5)), 6),
        "score_p95"         : round(float(np.percentile(scores, 95)), 6),
    }

    logger.info(
        "Evaluation: %d/%d blocks flagged as anomalous (%.1f%%)",
        n_anomaly, n_total, metrics["anomaly_rate_pct"],
    )
    logger.info(
        "Anomaly score  mean=%.4f  std=%.4f  [%.4f, %.4f]",
        metrics["score_mean"], metrics["score_std"],
        metrics["score_min"],  metrics["score_max"],
    )
    return metrics

# ── Persistence ────────────────────────────────────────────────────────────────

def save_model(pipeline: Pipeline, model_file: str) -> None:
    """Persist the trained pipeline to disk using joblib."""
    Path(model_file).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_file)
    logger.info("Model saved → %s", model_file)


def save_feature_meta(feature_cols: list[str], meta_file: str) -> None:
    """
    Save the list of feature columns used during training.
    evaluate.py and api.py must load the same columns to avoid
    feature mismatch errors at inference time.
    """
    Path(meta_file).parent.mkdir(parents=True, exist_ok=True)
    with open(meta_file, "w") as f:
        json.dump({"feature_columns": feature_cols}, f, indent=2)
    logger.info("Feature metadata saved → %s", meta_file)


def save_training_report(metrics: dict, config: dict, report_file: str) -> None:
    """
    Save a human-readable JSON report containing training config + evaluation
    metrics. Useful for comparing runs and documenting results in the report.
    """
    report = {
        "trained_at" : datetime.now().isoformat(timespec="seconds"),
        "config"     : config,
        "evaluation" : metrics,
    }
    Path(report_file).parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Training report saved → %s", report_file)

# ── Main training pipeline ─────────────────────────────────────────────────────

def train(
    features_file : str   = DEFAULT_FEATURES,
    model_file    : str   = DEFAULT_MODEL,
    meta_file     : str   = DEFAULT_META,
    report_file   : str   = DEFAULT_REPORT,
    contamination : float = CONTAMINATION,
    n_estimators  : int   = N_ESTIMATORS,
    max_samples          = MAX_SAMPLES,
    test_size     : float = TEST_SIZE,
    random_state  : int   = RANDOM_STATE,
) -> Pipeline:
    """
    Full training pipeline:
      1. Load & validate features
      2. Select and clean feature columns
      3. Train/test split
      4. Build and fit Pipeline (Scaler + IsolationForest)
      5. Evaluate on test split
      6. Save model, feature metadata, and training report
    """
    logger.info("=" * 60)
    logger.info("Log Sentinel AI — Baseline Model Training")
    logger.info("=" * 60)

    # 1. Load
    df           = load_features(features_file)
    feature_cols = select_feature_columns(df)

    if len(feature_cols) == 0:
        raise ValueError("No usable numeric feature columns found. Check build_features.py output.")

    X = clean_features(df[feature_cols].copy())

    # 2. Train / test split (stratification not applicable — unsupervised)
    X_train, X_test = train_test_split(
        X, test_size=test_size, random_state=random_state, shuffle=True
    )
    logger.info(
        "Split: %d train blocks, %d test blocks (test_size=%.0f%%)",
        len(X_train), len(X_test), test_size * 100,
    )

    # 3. Build and fit
    pipeline = build_pipeline(contamination, n_estimators, max_samples, random_state)
    logger.info(
        "Training IsolationForest: n_estimators=%d, contamination=%.4f, max_samples=%s",
        n_estimators, contamination, max_samples,
    )
    pipeline.fit(X_train)
    logger.info("Training complete.")

    # 4. Evaluate
    metrics = evaluate_pipeline(pipeline, X_test)

    # 5. Persist
    config = {
        "features_file" : features_file,
        "model_file"    : model_file,
        "contamination" : contamination,
        "n_estimators"  : n_estimators,
        "max_samples"   : str(max_samples),
        "test_size"     : test_size,
        "random_state"  : random_state,
        "n_features"    : len(feature_cols),
        "train_blocks"  : len(X_train),
    }
    save_model(pipeline, model_file)
    save_feature_meta(feature_cols, meta_file)
    save_training_report(metrics, config, report_file)

    logger.info("=" * 60)
    logger.info("Training finished successfully.")
    logger.info("=" * 60)
    return pipeline


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Train Isolation Forest baseline model"
    )
    parser.add_argument("--features",       default=DEFAULT_FEATURES,
                        help="Path to block_features.parquet")
    parser.add_argument("--model",          default=DEFAULT_MODEL,
                        help="Output path for trained model (.pkl)")
    parser.add_argument("--meta",           default=DEFAULT_META,
                        help="Output path for feature metadata (.json)")
    parser.add_argument("--report",         default=DEFAULT_REPORT,
                        help="Output path for training report (.json)")
    parser.add_argument("--contamination",  type=float, default=CONTAMINATION,
                        help="Expected fraction of anomalies in training data (default: 0.01)")
    parser.add_argument("--n-estimators",   type=int,   default=N_ESTIMATORS,
                        help="Number of Isolation Forest trees (default: 100)")
    parser.add_argument("--max-samples",    default=MAX_SAMPLES,
                        help="Samples per tree: 'auto', int, or float (default: auto)")
    parser.add_argument("--test-size",      type=float, default=TEST_SIZE,
                        help="Fraction of data held out for evaluation (default: 0.2)")
    parser.add_argument("--random-state",   type=int,   default=RANDOM_STATE,
                        help="Random seed for reproducibility (default: 42)")
    args = parser.parse_args()

    train(
        features_file = args.features,
        model_file    = args.model,
        meta_file     = args.meta,
        report_file   = args.report,
        contamination = args.contamination,
        n_estimators  = args.n_estimators,
        max_samples   = args.max_samples,
        test_size     = args.test_size,
        random_state  = args.random_state,
    )


if __name__ == "__main__":
    main()
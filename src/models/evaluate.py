"""
evaluate.py — Log Sentinel AI
=====================================
Evaluates the trained Isolation Forest model against ground-truth labels
from the HDFS anomaly_label.csv dataset.

Aligns with Chapter 5 (Testing, Evaluation, and Results) of the report:
  - Section 5.2: Experimental Setup   → loads features + labels, merges correctly
  - Section 5.3: Performance Metrics  → accuracy, precision, recall, F1, ROC-AUC
  - Section 5.4: Results and Analysis → saves full report + confusion matrix
  - Section 5.5: Security Evaluation  → per-threat-category hit analysis

Reads the feature column list from models/feature_meta.json (written by
train_baseline.py) to guarantee train/eval feature consistency.

Usage
-----
    python src/models/evaluate.py
    python src/models/evaluate.py --features data/features/block_features.parquet
    python src/models/evaluate.py --threshold -0.05
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_FEATURES = "data/features/block_features.parquet"
DEFAULT_LABELS   = "data/raw/hdfs/anomaly_label.csv"
DEFAULT_MODEL    = "models/isoforest.pkl"
DEFAULT_META     = "models/feature_meta.json"
DEFAULT_REPORT   = "models/evaluation_report.json"

# Threat categories defined in build_features.py (Table 3.1 of the report)
THREAT_CATEGORIES = [
    "brute_force", "privilege_esc", "dos",
    "log_tamper",  "startup",       "network",
]


# ── Loading helpers ────────────────────────────────────────────────────────────

def _require(path: Path, label: str) -> Path:
    """Raise a clear FileNotFoundError if a required file is missing."""
    if not path.exists():
        raise FileNotFoundError(
            f"{label} not found: {path.resolve()}\n"
            "Make sure you have run build_features.py and train_baseline.py first."
        )
    return path


# Known column renames between build_features.py versions.
# Add any future renames here so evaluate.py never needs to crash on them.
COLUMN_RENAMES: dict[str, str] = {
    "block_duration"    : "block_duration_sec",   # v1 → v2 rename
    "block_duration_sec": "block_duration",        # v2 → v1 (reverse)
}


def load_feature_columns(meta_file: str) -> list[str] | None:
    """
    Load the feature column list saved by train_baseline.py.
    Returns None if the file doesn't exist (fallback to auto-detection).
    """
    path = Path(meta_file)
    if not path.exists():
        logger.warning(
            "Feature metadata not found at %s — will auto-detect columns.\n"
            "Re-run train_baseline.py to generate it and avoid feature mismatch.",
            meta_file,
        )
        return None
    with open(path) as f:
        meta = json.load(f)
    cols = meta.get("feature_columns", [])
    logger.info("Loaded %d feature columns from metadata.", len(cols))
    return cols


def load_and_merge(features_file: str, labels_file: str) -> pd.DataFrame:
    """
    Load block_features.parquet and anomaly_label.csv, merge on block_id.
    anomaly_label.csv is expected to have columns: BlockId, Label
      where Label ∈ {"Normal", "Anomaly"}.
    """
    feats  = pd.read_parquet(_require(Path(features_file), "Features file"))
    labels = pd.read_csv(_require(Path(labels_file), "Labels file"))

    logger.info("Features shape: %s", feats.shape)
    logger.info("Labels shape  : %s", labels.shape)

    # Normalise column names for robust merging
    labels.columns = labels.columns.str.strip()
    if "BlockId" not in labels.columns or "Label" not in labels.columns:
        raise ValueError(
            f"anomaly_label.csv must contain 'BlockId' and 'Label' columns. "
            f"Found: {list(labels.columns)}"
        )

    df = feats.merge(labels, left_on="block_id", right_on="BlockId", how="inner")
    logger.info(
        "Merged dataset: %d blocks (%d in features, %d in labels).",
        len(df), len(feats), len(labels),
    )

    if len(df) == 0:
        raise ValueError(
            "Merge produced 0 rows — block_id values do not match BlockId values. "
            "Check that the same log file was used for both parsing and labelling."
        )

    n_anomaly = (df["Label"] == "Anomaly").sum()
    n_normal  = (df["Label"] == "Normal").sum()
    logger.info("Label distribution: %d Normal, %d Anomaly.", n_normal, n_anomaly)
    return df


def _reconcile_columns(
    wanted: list[str],
    available: set[str],
    model_n_features: int,
) -> tuple[list[str], dict[str, str]]:
    """
    Reconcile the column list from feature_meta.json against the columns
    that actually exist in the current feature file.

    Returns
    -------
    resolved   : list of column names to SELECT from the dataframe
    rename_map : {dataframe_col → model_col} renames to apply AFTER selection
                 so that X columns match exactly what the model was trained on

    Strategy (in order):
      1. Keep every wanted column that is directly present.
      2. For each missing column, check COLUMN_RENAMES for a known alias
         that IS present — select the alias but record a rename back to the
         original name the model was trained on.
      3. After substitution, if resolved count == model_n_features → done.
      4. Otherwise fall back to auto-selecting from available numeric columns.
    """
    resolved: list[str]    = []   # names to SELECT from df
    rename_map: dict[str, str] = {}  # alias_col → original_model_col
    still_missing: list[str] = []

    for col in wanted:
        if col in available:
            resolved.append(col)
        elif col in COLUMN_RENAMES and COLUMN_RENAMES[col] in available:
            alias = COLUMN_RENAMES[col]
            logger.warning(
                "Column '%s' not in feature file — selecting '%s' and renaming "
                "it to '%s' to match the trained model.",
                col, alias, col,
            )
            resolved.append(alias)
            rename_map[alias] = col          # rename alias → original after select
        else:
            still_missing.append(col)

    if still_missing:
        logger.warning(
            "Could not resolve %d column(s) from metadata: %s",
            len(still_missing), still_missing,
        )

    if len(resolved) == model_n_features:
        logger.info("Column reconciliation successful: using %d columns.", len(resolved))
        return resolved, rename_map

    # Fallback: auto-select the right number of numeric columns
    logger.warning(
        "Resolved %d columns but model expects %d. "
        "Falling back to auto-selecting %d numeric columns. "
        "Re-run train_baseline.py with the current build_features.py to fix properly.",
        len(resolved), model_n_features, model_n_features,
    )
    EXCLUDE = {"block_id", "BlockId", "Label", "label", "anomaly", "split"}
    auto = [c for c in available if c not in EXCLUDE][:model_n_features]
    if len(auto) < model_n_features:
        raise ValueError(
            f"Feature file has only {len(auto)} usable numeric columns "
            f"but model expects {model_n_features}. "
            "Run build_features.py then train_baseline.py to regenerate everything."
        )
    return auto, {}


def prepare_features(
    df: pd.DataFrame,
    feature_cols: list[str] | None,
    model,
) -> tuple[pd.DataFrame, list[str]]:
    """
    Select and clean feature matrix X so it is always compatible with the
    loaded model, even when build_features.py has changed column names.

    Resolution order
    ----------------
    1. Metadata columns present as-is            → use them directly
    2. Missing metadata column has a known rename → substitute silently
    3. Count still wrong after substitution       → auto-select from available,
                                                    warn loudly
    4. No metadata at all                         → auto-detect all numeric cols
    """
    EXCLUDE = {"block_id", "BlockId", "Label", "label", "anomaly", "split"}

    # Determine how many features the model was trained on
    try:
        model_n_features: int = model.n_features_in_
    except AttributeError:
        # Older sklearn versions; try to read from the scaler step if Pipeline
        try:
            model_n_features = model.named_steps["scaler"].n_features_in_
        except (AttributeError, KeyError):
            model_n_features = len(feature_cols) if feature_cols else 0

    available_numeric = {
        c for c in df.columns
        if c not in EXCLUDE and pd.api.types.is_numeric_dtype(df[c])
    }

    if feature_cols is not None:
        cols, rename_map = _reconcile_columns(feature_cols, available_numeric, model_n_features)
    else:
        cols       = list(available_numeric)
        rename_map = {}
        if model_n_features and len(cols) != model_n_features:
            logger.warning(
                "Auto-detected %d columns but model expects %d — truncating.",
                len(cols), model_n_features,
            )
            cols = cols[:model_n_features]
        logger.info("Auto-detected %d feature columns.", len(cols))

    X = df[cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median(numeric_only=True))

    # Rename aliased columns back to the names the model was trained on
    if rename_map:
        X = X.rename(columns=rename_map)
        logger.info("Renamed columns to match trained model: %s", rename_map)

    logger.info("Feature matrix ready: %d rows × %d cols.", len(X), len(X.columns))
    return X, list(X.columns)


# ── Metrics ────────────────────────────────────────────────────────────────────

def compute_metrics(y_true: pd.Series, y_pred: np.ndarray,
                    scores: np.ndarray, threshold: float | None) -> dict:
    """
    Compute the full set of evaluation metrics described in Section 5.3.

    Parameters
    ----------
    y_true     : ground-truth labels (+1 normal, -1 anomaly)
    y_pred     : model predictions (+1 / -1)
    scores     : raw decision_function output (higher = more normal)
    threshold  : if provided, re-derive y_pred by thresholding scores
                 (scores < threshold → anomaly), allowing precision/recall tuning
    """
    if threshold is not None:
        y_pred = np.where(scores < threshold, -1, 1)
        logger.info("Applying custom score threshold: %.4f", threshold)

    # ── Confusion matrix ───────────────────────────────────────────────────────
    cm = confusion_matrix(y_true, y_pred, labels=[-1, 1])
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, len(y_true))

    # For ROC-AUC: use raw scores (higher = normal = +1); negate for anomaly probability
    y_binary = (y_true == -1).astype(int)          # 1 = anomaly
    anomaly_score = -scores                         # higher = more anomalous

    try:
        roc_auc = float(roc_auc_score(y_binary, anomaly_score))
    except ValueError:
        roc_auc = None
        logger.warning("ROC-AUC could not be computed (only one class in labels).")

    try:
        avg_precision = float(average_precision_score(y_binary, anomaly_score))
    except ValueError:
        avg_precision = None

    clf_report = classification_report(
        y_true, y_pred,
        labels=[-1, 1],
        target_names=["Anomaly", "Normal"],
        output_dict=True,
        zero_division=0,
    )

    return {
        "threshold"         : threshold,
        "true_positives"    : int(tp),
        "true_negatives"    : int(tn),
        "false_positives"   : int(fp),
        "false_negatives"   : int(fn),
        "accuracy"          : round((tp + tn) / len(y_true), 4),
        "precision_anomaly" : round(clf_report["Anomaly"]["precision"], 4),
        "recall_anomaly"    : round(clf_report["Anomaly"]["recall"],    4),
        "f1_anomaly"        : round(clf_report["Anomaly"]["f1-score"],  4),
        "precision_normal"  : round(clf_report["Normal"]["precision"],  4),
        "recall_normal"     : round(clf_report["Normal"]["recall"],     4),
        "f1_normal"         : round(clf_report["Normal"]["f1-score"],   4),
        "roc_auc"           : round(roc_auc, 4) if roc_auc is not None else None,
        "avg_precision"     : round(avg_precision, 4) if avg_precision is not None else None,
        "classification_report": clf_report,
    }


def threat_category_analysis(df: pd.DataFrame,
                              y_true: pd.Series,
                              y_pred: np.ndarray) -> dict:
    """
    Per-threat-category analysis (Section 5.5 — Security Evaluation).

    For each threat category defined in the report's Table 3.1, report:
      - how many anomalous blocks had at least one keyword hit
      - how many of those were correctly detected by the model
    This validates that the threat keyword features are meaningful signals.
    """
    results = {}
    for cat in THREAT_CATEGORIES:
        col = f"{cat}_hits"
        if col not in df.columns:
            continue

        hit_mask        = df[col] > 0
        n_hits          = int(hit_mask.sum())
        n_true_anomaly  = int(((y_true == -1) & hit_mask).sum())
        n_detected      = int(((y_pred == -1) & (y_true == -1) & hit_mask).sum())

        results[cat] = {
            "blocks_with_hits"     : n_hits,
            "true_anomaly_hits"    : n_true_anomaly,
            "correctly_detected"   : n_detected,
            "detection_rate_pct"   : round(
                100 * n_detected / n_true_anomaly, 1
            ) if n_true_anomaly > 0 else None,
        }

    return results


def print_summary(metrics: dict, threat: dict) -> None:
    """Print a clean, report-ready summary to stdout."""
    sep = "─" * 60
    logger.info(sep)
    logger.info("EVALUATION RESULTS")
    logger.info(sep)
    logger.info("Accuracy          : %.4f", metrics["accuracy"])
    logger.info("Precision (Anomaly): %.4f", metrics["precision_anomaly"])
    logger.info("Recall    (Anomaly): %.4f", metrics["recall_anomaly"])
    logger.info("F1-Score  (Anomaly): %.4f", metrics["f1_anomaly"])
    if metrics["roc_auc"] is not None:
        logger.info("ROC-AUC           : %.4f", metrics["roc_auc"])
    if metrics["avg_precision"] is not None:
        logger.info("Avg Precision     : %.4f", metrics["avg_precision"])
    logger.info("Confusion Matrix  : TP=%d  TN=%d  FP=%d  FN=%d",
                metrics["true_positives"],  metrics["true_negatives"],
                metrics["false_positives"], metrics["false_negatives"])
    logger.info(sep)
    logger.info("THREAT CATEGORY DETECTION (Section 5.5)")
    logger.info(sep)
    for cat, stats in threat.items():
        if stats["true_anomaly_hits"] > 0:
            logger.info(
                "%-18s  hits=%d  anomalies=%d  detected=%d  rate=%s%%",
                cat,
                stats["blocks_with_hits"],
                stats["true_anomaly_hits"],
                stats["correctly_detected"],
                stats["detection_rate_pct"],
            )
    logger.info(sep)


# ── Main ───────────────────────────────────────────────────────────────────────

def evaluate(
    features_file : str        = DEFAULT_FEATURES,
    labels_file   : str        = DEFAULT_LABELS,
    model_file    : str        = DEFAULT_MODEL,
    meta_file     : str        = DEFAULT_META,
    report_file   : str        = DEFAULT_REPORT,
    threshold     : float|None = None,
) -> dict:
    """
    Full evaluation pipeline:
      1. Load model + feature metadata
      2. Load and merge features with ground-truth labels
      3. Prepare feature matrix (consistent with training)
      4. Predict and compute metrics
      5. Threat-category security analysis
      6. Save evaluation report to JSON
    """
    logger.info("=" * 60)
    logger.info("Log Sentinel AI — Model Evaluation")
    logger.info("=" * 60)

    # 1. Load model
    _require(Path(model_file), "Model file")
    model        = joblib.load(model_file)
    feature_cols = load_feature_columns(meta_file)
    logger.info("Model loaded from %s", model_file)

    # 2. Load & merge data
    df = load_and_merge(features_file, labels_file)

    # 3. Prepare features (resilient to column renames / version drift)
    X, used_cols = prepare_features(df, feature_cols, model)

    # 4. Map ground-truth labels to Isolation Forest convention
    #    Normal → +1,  Anomaly → -1
    y_true = df["Label"].map({"Normal": 1, "Anomaly": -1})
    unmapped = y_true.isna().sum()
    if unmapped > 0:
        logger.warning(
            "%d rows had unrecognised Label values and will be dropped.", unmapped
        )
        mask   = y_true.notna()
        y_true = y_true[mask]
        X      = X[mask]
        df     = df[mask]
    y_true = y_true.astype(int)

    # 5. Predict
    scores = model.decision_function(X)
    y_pred = model.predict(X)

    # 6. Metrics
    metrics = compute_metrics(y_true, y_pred, scores, threshold)
    threat  = threat_category_analysis(df, y_true, y_pred)

    print_summary(metrics, threat)

    # 7. Save report
    report = {
        "evaluated_at"    : datetime.now().isoformat(timespec="seconds"),
        "features_file"   : str(features_file),
        "model_file"      : str(model_file),
        "n_features"      : len(used_cols),
        "feature_columns" : used_cols,
        "n_blocks"        : len(y_true),
        "metrics"         : metrics,
        "threat_analysis" : threat,
    }
    Path(report_file).parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Evaluation report saved → %s", report_file)

    return report


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Evaluate trained Isolation Forest model"
    )
    parser.add_argument("--features",  default=DEFAULT_FEATURES,
                        help="Path to block_features.parquet")
    parser.add_argument("--labels",    default=DEFAULT_LABELS,
                        help="Path to anomaly_label.csv")
    parser.add_argument("--model",     default=DEFAULT_MODEL,
                        help="Path to trained model .pkl")
    parser.add_argument("--meta",      default=DEFAULT_META,
                        help="Path to feature_meta.json from training")
    parser.add_argument("--report",    default=DEFAULT_REPORT,
                        help="Output path for evaluation_report.json")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Custom anomaly score threshold (overrides model default). "
                             "Scores below this value are flagged as anomalous. "
                             "Use to tune precision/recall trade-off.")
    args = parser.parse_args()

    try:
        evaluate(
            features_file = args.features,
            labels_file   = args.labels,
            model_file    = args.model,
            meta_file     = args.meta,
            report_file   = args.report,
            threshold     = args.threshold,
        )
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
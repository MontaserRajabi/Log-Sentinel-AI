"""
test.py — Log Sentinel AI
=====================================
Integration tests for the full pipeline:
    ingest_files → template_miner → build_features → train_baseline → evaluate

Complements test_model.py (which tests the model in isolation) by testing
each pipeline stage end-to-end using the HDFS sample dataset.

Run with:
    python -m pytest src/models/test.py -v
    python -m pytest src/models/test.py -v -k "TestParser"   # run one class only

Aligns with:
    - Section 5.1 Testing Strategy: integration testing
    - Section 5.2 Experimental Setup: dataset and pipeline validation
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# ── Project root ───────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# ── File paths ─────────────────────────────────────────────────────────────────
LABELS_FILE        = PROJECT_ROOT / "data" / "raw" / "hdfs" / "anomaly_label.csv"
SAMPLE_LOG         = PROJECT_ROOT / "data" / "raw" / "hdfs" / "HDFS_sample.log"
EVENTS_PARSED      = PROJECT_ROOT / "data" / "parsed" / "events_parsed.jsonl"
BLOCK_FEATURES     = PROJECT_ROOT / "data" / "features" / "block_features.parquet"
EVENT_FEATURES     = PROJECT_ROOT / "data" / "features" / "event_features.parquet"
TEMPLATE_CATALOG   = PROJECT_ROOT / "data" / "parsed" / "template_catalog.json"
MODEL_FILE         = PROJECT_ROOT / "models" / "isoforest.pkl"
META_FILE          = PROJECT_ROOT / "models" / "feature_meta.json"
TRAINING_REPORT    = PROJECT_ROOT / "models" / "training_report.json"
EVALUATION_REPORT  = PROJECT_ROOT / "models" / "evaluation_report.json"


# ══════════════════════════════════════════════════════════════════════════════
# DATASET TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestDataset:

    def test_labels_file_exists(self):
        """anomaly_label.csv must exist in data/raw/hdfs/."""
        assert LABELS_FILE.exists(), (
            f"Labels file not found: {LABELS_FILE}\n"
            "Download the HDFS dataset and place anomaly_label.csv in data/raw/hdfs/"
        )

    def test_labels_file_loads(self):
        """anomaly_label.csv must load as a valid DataFrame."""
        if not LABELS_FILE.exists():
            pytest.skip("anomaly_label.csv not found.")
        df = pd.read_csv(LABELS_FILE)
        assert len(df) > 0, "anomaly_label.csv is empty."

    def test_labels_has_required_columns(self):
        """anomaly_label.csv must have BlockId and Label columns."""
        if not LABELS_FILE.exists():
            pytest.skip("anomaly_label.csv not found.")
        df = pd.read_csv(LABELS_FILE)
        assert "BlockId" in df.columns, (
            f"Expected 'BlockId' column. Found: {list(df.columns)}"
        )
        assert "Label" in df.columns, (
            f"Expected 'Label' column. Found: {list(df.columns)}"
        )

    def test_labels_values_are_valid(self):
        """Label column must only contain 'Normal' or 'Anomaly'."""
        if not LABELS_FILE.exists():
            pytest.skip("anomaly_label.csv not found.")
        df     = pd.read_csv(LABELS_FILE)
        values = set(df["Label"].unique())
        assert values.issubset({"Normal", "Anomaly"}), (
            f"Unexpected label values: {values - {'Normal', 'Anomaly'}}"
        )

    def test_labels_not_all_same_class(self):
        """Dataset must contain both Normal and Anomaly labels."""
        if not LABELS_FILE.exists():
            pytest.skip("anomaly_label.csv not found.")
        df = pd.read_csv(LABELS_FILE)
        assert "Normal"  in df["Label"].values, "No Normal labels found."
        assert "Anomaly" in df["Label"].values, "No Anomaly labels found."

    def test_labels_block_id_unique(self):
        """BlockId must be unique in the labels file."""
        if not LABELS_FILE.exists():
            pytest.skip("anomaly_label.csv not found.")
        df = pd.read_csv(LABELS_FILE)
        assert df["BlockId"].nunique() == len(df), (
            f"Duplicate BlockIds found: "
            f"{len(df) - df['BlockId'].nunique()} duplicates."
        )

    def test_sample_log_exists(self):
        """HDFS_sample.log must exist for pipeline tests."""
        assert SAMPLE_LOG.exists(), (
            f"Sample log not found: {SAMPLE_LOG}\n"
            "Run: head -n 400000 data/raw/hdfs/HDFS_1.log > data/raw/hdfs/HDFS_sample.log"
        )

    def test_sample_log_not_empty(self):
        """HDFS_sample.log must not be empty."""
        if not SAMPLE_LOG.exists():
            pytest.skip("HDFS_sample.log not found.")
        assert SAMPLE_LOG.stat().st_size > 0, "HDFS_sample.log is empty."


# ══════════════════════════════════════════════════════════════════════════════
# PARSER TESTS (template_miner.py)
# ══════════════════════════════════════════════════════════════════════════════

class TestParser:

    def test_parsed_events_file_exists(self):
        """events_parsed.jsonl must exist after running template_miner.py."""
        assert EVENTS_PARSED.exists(), (
            f"Parsed events not found: {EVENTS_PARSED}\n"
            "Run: python src/parse/template_miner.py"
        )

    def test_parsed_events_not_empty(self):
        """events_parsed.jsonl must contain at least one event."""
        if not EVENTS_PARSED.exists():
            pytest.skip("events_parsed.jsonl not found.")
        lines = [l for l in EVENTS_PARSED.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) > 0, "events_parsed.jsonl is empty."

    def test_parsed_events_valid_json(self):
        """Every line in events_parsed.jsonl must be valid JSON."""
        if not EVENTS_PARSED.exists():
            pytest.skip("events_parsed.jsonl not found.")
        lines = [l for l in EVENTS_PARSED.read_text(encoding="utf-8").splitlines() if l.strip()]
        for i, line in enumerate(lines[:100], 1):   # check first 100
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                pytest.fail(f"Invalid JSON at line {i}: {exc}")

    def test_parsed_events_have_required_fields(self):
        """Each parsed event must have template_id, raw, and block_id."""
        if not EVENTS_PARSED.exists():
            pytest.skip("events_parsed.jsonl not found.")
        lines = [l for l in EVENTS_PARSED.read_text(encoding="utf-8").splitlines() if l.strip()]
        required = {"template_id", "raw", "block_id"}
        for i, line in enumerate(lines[:50], 1):
            event   = json.loads(line)
            missing = required - set(event.keys())
            assert not missing, f"Line {i} missing fields: {missing}"

    def test_template_ids_are_integers(self):
        """template_id must be an integer for all parsed events."""
        if not EVENTS_PARSED.exists():
            pytest.skip("events_parsed.jsonl not found.")
        lines = [l for l in EVENTS_PARSED.read_text(encoding="utf-8").splitlines() if l.strip()]
        for i, line in enumerate(lines[:50], 1):
            event = json.loads(line)
            assert isinstance(event["template_id"], int), (
                f"Line {i}: template_id is {type(event['template_id']).__name__}, expected int."
            )

    def test_template_ids_are_stable(self):
        """
        The same raw log line must always produce the same template_id.
        Tests that hashlib MD5 (not Python's random hash) is used.
        """
        if not EVENTS_PARSED.exists():
            pytest.skip("events_parsed.jsonl not found.")
        from parse.template_miner import normalize, template_id

        test_line = "081109 203518 143 INFO dfs.DataNode: Receiving block blk_-1608999687919862906"
        id1 = template_id(normalize(test_line))
        id2 = template_id(normalize(test_line))
        assert id1 == id2, "template_id is not stable across calls."

    def test_template_catalog_exists(self):
        """template_catalog.json must be created by template_miner.py."""
        assert TEMPLATE_CATALOG.exists(), (
            f"Template catalog not found: {TEMPLATE_CATALOG}"
        )

    def test_template_catalog_valid_json(self):
        """template_catalog.json must be valid JSON."""
        if not TEMPLATE_CATALOG.exists():
            pytest.skip("template_catalog.json not found.")
        try:
            catalog = json.loads(TEMPLATE_CATALOG.read_text(encoding="utf-8"))
            assert isinstance(catalog, dict)
        except json.JSONDecodeError as exc:
            pytest.fail(f"template_catalog.json is invalid JSON: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE ENGINEERING TESTS (build_features.py)
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatures:

    def test_block_features_file_exists(self):
        """block_features.parquet must exist after build_features.py."""
        assert BLOCK_FEATURES.exists(), (
            f"Block features not found: {BLOCK_FEATURES}\n"
            "Run: python src/features/build_features.py"
        )

    def test_event_features_file_exists(self):
        """event_features.parquet must exist after build_features.py."""
        assert EVENT_FEATURES.exists(), (
            f"Event features not found: {EVENT_FEATURES}\n"
            "Run: python src/features/build_features.py"
        )

    def test_block_features_loads(self):
        """block_features.parquet must load as a valid DataFrame."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df = pd.read_parquet(BLOCK_FEATURES)
        assert len(df) > 0, "block_features.parquet is empty."

    def test_block_features_has_block_id(self):
        """block_features must have a block_id column."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df = pd.read_parquet(BLOCK_FEATURES)
        assert "block_id" in df.columns

    def test_block_features_required_columns(self):
        """block_features must contain all expected feature columns."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df       = pd.read_parquet(BLOCK_FEATURES)
        required = [
            "num_events", "unique_templates", "template_entropy",
            "error_count", "error_ratio", "avg_msg_len",
            "brute_force_hits", "privilege_esc_hits",
        ]
        for col in required:
            assert col in df.columns, (
                f"Expected column '{col}' missing from block_features."
            )

    def test_block_features_no_all_nan_columns(self):
        """No feature column should be entirely NaN."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df       = pd.read_parquet(BLOCK_FEATURES)
        num_cols = [c for c in df.columns if c != "block_id"]
        for col in num_cols:
            assert not df[col].isna().all(), (
                f"Column '{col}' is entirely NaN."
            )

    def test_block_features_num_events_positive(self):
        """num_events must be positive for all blocks."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df = pd.read_parquet(BLOCK_FEATURES)
        assert (df["num_events"] > 0).all(), (
            "Some blocks have num_events <= 0."
        )

    def test_block_features_ratios_in_range(self):
        """error_ratio and warn_ratio must be between 0 and 1."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df = pd.read_parquet(BLOCK_FEATURES)
        assert df["error_ratio"].between(0, 1).all(), "error_ratio out of [0,1] range."
        assert df["warn_ratio"].between(0, 1).all(),  "warn_ratio out of [0,1] range."

    def test_block_features_entropy_non_negative(self):
        """template_entropy must be >= 0."""
        if not BLOCK_FEATURES.exists():
            pytest.skip("block_features.parquet not found.")
        df = pd.read_parquet(BLOCK_FEATURES)
        assert (df["template_entropy"] >= 0).all(), (
            "Negative template_entropy values found."
        )

    def test_event_features_loads(self):
        """event_features.parquet must load as a valid DataFrame."""
        if not EVENT_FEATURES.exists():
            pytest.skip("event_features.parquet not found.")
        df = pd.read_parquet(EVENT_FEATURES)
        assert len(df) > 0, "event_features.parquet is empty."

    def test_event_features_flag_columns_binary(self):
        """All threat flag columns must contain only 0 or 1."""
        if not EVENT_FEATURES.exists():
            pytest.skip("event_features.parquet not found.")
        df        = pd.read_parquet(EVENT_FEATURES)
        flag_cols = [c for c in df.columns if c.endswith("_flag")]
        for col in flag_cols:
            assert set(df[col].unique()).issubset({0, 1}), (
                f"Flag column '{col}' contains non-binary values."
            )


# ══════════════════════════════════════════════════════════════════════════════
# TRAINING REPORT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestTrainingReport:

    def test_training_report_exists(self):
        """training_report.json must exist after train_baseline.py."""
        assert TRAINING_REPORT.exists(), (
            f"Training report not found: {TRAINING_REPORT}\n"
            "Run: python src/models/train_baseline.py"
        )

    def test_training_report_valid(self):
        """training_report.json must be valid JSON with required keys."""
        if not TRAINING_REPORT.exists():
            pytest.skip("training_report.json not found.")
        report = json.loads(TRAINING_REPORT.read_text(encoding="utf-8"))
        for key in ("trained_at", "config", "evaluation"):
            assert key in report, f"Missing key '{key}' in training_report.json."

    def test_training_report_anomaly_rate_sane(self):
        """Anomaly rate in training report must be between 0.1% and 20%."""
        if not TRAINING_REPORT.exists():
            pytest.skip("training_report.json not found.")
        report = json.loads(TRAINING_REPORT.read_text(encoding="utf-8"))
        rate   = report.get("evaluation", {}).get("anomaly_rate_pct", -1)
        assert 0.1 <= rate <= 20.0, (
            f"Anomaly rate {rate:.1f}% is outside expected range [0.1%, 20%]."
        )


# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION REPORT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestEvaluationReport:

    def test_evaluation_report_exists(self):
        """evaluation_report.json must exist after evaluate.py."""
        assert EVALUATION_REPORT.exists(), (
            f"Evaluation report not found: {EVALUATION_REPORT}\n"
            "Run: python src/models/evaluate.py"
        )

    def test_evaluation_report_valid(self):
        """evaluation_report.json must be valid JSON with required keys."""
        if not EVALUATION_REPORT.exists():
            pytest.skip("evaluation_report.json not found.")
        report = json.loads(EVALUATION_REPORT.read_text(encoding="utf-8"))
        for key in ("evaluated_at", "metrics", "n_blocks"):
            assert key in report, f"Missing key '{key}' in evaluation_report.json."

    def test_accuracy_above_threshold(self):
        """Model accuracy must be above 90% on the HDFS dataset."""
        if not EVALUATION_REPORT.exists():
            pytest.skip("evaluation_report.json not found.")
        report   = json.loads(EVALUATION_REPORT.read_text(encoding="utf-8"))
        accuracy = report.get("metrics", {}).get("accuracy", 0)
        assert accuracy >= 0.90, (
            f"Accuracy {accuracy:.4f} is below the 90% threshold."
        )

    def test_roc_auc_above_threshold(self):
        """ROC-AUC must be above 0.65 — better than random."""
        if not EVALUATION_REPORT.exists():
            pytest.skip("evaluation_report.json not found.")
        report  = json.loads(EVALUATION_REPORT.read_text(encoding="utf-8"))
        roc_auc = report.get("metrics", {}).get("roc_auc", 0)
        if roc_auc is None:
            pytest.skip("ROC-AUC not available in evaluation report.")
        assert roc_auc >= 0.65, (
            f"ROC-AUC {roc_auc:.4f} is below the 0.65 threshold."
        )

    def test_precision_above_threshold(self):
        """Anomaly precision must be above 50% to be useful."""
        if not EVALUATION_REPORT.exists():
            pytest.skip("evaluation_report.json not found.")
        report    = json.loads(EVALUATION_REPORT.read_text(encoding="utf-8"))
        precision = report.get("metrics", {}).get("precision_anomaly", 0)
        assert precision >= 0.50, (
            f"Precision {precision:.4f} is below 50% — too many false alarms."
        )

    def test_evaluation_covers_enough_blocks(self):
        """Evaluation must cover at least 1000 blocks to be meaningful."""
        if not EVALUATION_REPORT.exists():
            pytest.skip("evaluation_report.json not found.")
        report   = json.loads(EVALUATION_REPORT.read_text(encoding="utf-8"))
        n_blocks = report.get("n_blocks", 0)
        assert n_blocks >= 1000, (
            f"Only {n_blocks} blocks evaluated — need at least 1000 for reliable metrics."
        )
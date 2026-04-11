"""
test_model.py — Log Sentinel AI
=====================================
Unit and integration tests for the trained Isolation Forest model.

Covers:
  - Model file exists and loads correctly
  - Feature metadata exists and is consistent with the model
  - Model produces valid predictions and scores
  - Anomaly score direction is correct (anomalous input scores lower)
  - Pipeline (Scaler + IsolationForest) works end-to-end
  - Model handles edge cases: all-zero input, NaN, inf, single row

Run with:
    pytest src/models/test_model.py -v
    pytest src/models/test_model.py -v --tb=short

Aligns with:
    - Section 5.1 Testing Strategy: unit testing
    - Section 5.2 Experimental Setup: model validation
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

# ── Project root resolution ────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

MODEL_FILE   = PROJECT_ROOT / "models" / "isoforest.pkl"
META_FILE    = PROJECT_ROOT / "models" / "feature_meta.json"
FEATURES_FILE = PROJECT_ROOT / "data" / "features" / "block_features.parquet"


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def model():
    """Load and return the trained model pipeline."""
    assert MODEL_FILE.exists(), (
        f"Model file not found: {MODEL_FILE}\n"
        "Run train_baseline.py first."
    )
    return joblib.load(MODEL_FILE)


@pytest.fixture(scope="module")
def feature_cols():
    """Load and return the feature column list from metadata."""
    assert META_FILE.exists(), (
        f"Feature metadata not found: {META_FILE}\n"
        "Run train_baseline.py first."
    )
    with open(META_FILE) as f:
        meta = json.load(f)
    cols = meta.get("feature_columns", [])
    assert len(cols) > 0, "feature_meta.json has no feature_columns."
    return cols


@pytest.fixture(scope="module")
def sample_features(feature_cols):
    """
    Build a small DataFrame of test rows using the training feature columns.
    Uses realistic value ranges based on HDFS log characteristics.
    """
    normal_row = {col: 0.0 for col in feature_cols}
    normal_row.update({
        "num_events"         : 12.0,
        "unique_templates"   : 4.0,
        "avg_msg_len"        : 120.0,
        "std_msg_len"        : 15.0,
        "max_msg_len"        : 180.0,
        "min_msg_len"        : 80.0,
        "error_count"        : 0.0,
        "warn_count"         : 1.0,
        "info_count"         : 11.0,
        "error_ratio"        : 0.0,
        "warn_ratio"         : 0.083,
        "template_entropy"   : 1.5,
        "top_template_ratio" : 0.6,
        "block_duration_sec" : 2.0,
        "events_per_sec"     : 6.0,
        "gap_count"          : 0.0,
    })

    # Anomalous row: many errors, high entropy, brute force hits
    anomaly_row = {col: 0.0 for col in feature_cols}
    anomaly_row.update({
        "num_events"         : 500.0,
        "unique_templates"   : 50.0,
        "avg_msg_len"        : 50.0,
        "std_msg_len"        : 5.0,
        "max_msg_len"        : 60.0,
        "min_msg_len"        : 40.0,
        "error_count"        : 480.0,
        "warn_count"         : 10.0,
        "info_count"         : 10.0,
        "error_ratio"        : 0.96,
        "warn_ratio"         : 0.02,
        "template_entropy"   : 5.0,
        "top_template_ratio" : 0.95,
        "block_duration_sec" : 0.5,
        "events_per_sec"     : 1000.0,
        "gap_count"          : 50.0,
        "brute_force_hits"   : 200.0,
    })

    return pd.DataFrame([normal_row, anomaly_row])[feature_cols]


# ══════════════════════════════════════════════════════════════════════════════
# MODEL FILE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestModelFile:

    def test_model_file_exists(self):
        """Model file must exist after training."""
        assert MODEL_FILE.exists(), f"Missing: {MODEL_FILE}"

    def test_meta_file_exists(self):
        """Feature metadata file must exist after training."""
        assert META_FILE.exists(), f"Missing: {META_FILE}"

    def test_model_loads_without_error(self, model):
        """Model must load without raising any exception."""
        assert model is not None

    def test_model_is_pipeline(self, model):
        """Model must be a sklearn Pipeline (Scaler + IsolationForest)."""
        assert isinstance(model, Pipeline), (
            f"Expected sklearn Pipeline, got {type(model).__name__}"
        )

    def test_pipeline_has_scaler(self, model):
        """Pipeline must contain a StandardScaler step."""
        from sklearn.preprocessing import StandardScaler
        assert "scaler" in model.named_steps, "Pipeline missing 'scaler' step."
        assert isinstance(model.named_steps["scaler"], StandardScaler)

    def test_pipeline_has_isolation_forest(self, model):
        """Pipeline must contain an IsolationForest step."""
        from sklearn.ensemble import IsolationForest
        assert "iforest" in model.named_steps, "Pipeline missing 'iforest' step."
        assert isinstance(model.named_steps["iforest"], IsolationForest)

    def test_model_is_fitted(self, model):
        """Model must be fitted (has n_features_in_ attribute)."""
        assert hasattr(model, "n_features_in_"), (
            "Model does not appear to be fitted — n_features_in_ missing."
        )
        assert model.n_features_in_ > 0


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE METADATA TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureMetadata:

    def test_feature_cols_not_empty(self, feature_cols):
        """Feature metadata must contain at least one column."""
        assert len(feature_cols) > 0

    def test_feature_cols_match_model(self, model, feature_cols):
        """Number of feature columns must match what the model was trained on."""
        assert model.n_features_in_ == len(feature_cols), (
            f"Model expects {model.n_features_in_} features "
            f"but metadata lists {len(feature_cols)}."
        )

    def test_feature_cols_are_strings(self, feature_cols):
        """All feature column names must be strings."""
        non_strings = [c for c in feature_cols if not isinstance(c, str)]
        assert len(non_strings) == 0, f"Non-string column names: {non_strings}"

    def test_no_duplicate_feature_cols(self, feature_cols):
        """Feature column list must not contain duplicates."""
        assert len(feature_cols) == len(set(feature_cols)), (
            "Duplicate feature columns found in metadata."
        )

    def test_expected_columns_present(self, feature_cols):
        """Core feature columns from build_features.py must be present."""
        expected = [
            "num_events", "unique_templates", "template_entropy",
            "error_count", "error_ratio", "avg_msg_len",
        ]
        for col in expected:
            assert col in feature_cols, (
                f"Expected column '{col}' not found in feature metadata."
            )


# ══════════════════════════════════════════════════════════════════════════════
# PREDICTION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestPredictions:

    def test_predict_returns_array(self, model, sample_features):
        """model.predict() must return a numpy array."""
        preds = model.predict(sample_features)
        assert isinstance(preds, np.ndarray)

    def test_predict_correct_length(self, model, sample_features):
        """Prediction array length must match input rows."""
        preds = model.predict(sample_features)
        assert len(preds) == len(sample_features)

    def test_predict_values_are_valid(self, model, sample_features):
        """All predictions must be either +1 (normal) or -1 (anomaly)."""
        preds = model.predict(sample_features)
        assert set(preds).issubset({1, -1}), (
            f"Unexpected prediction values: {set(preds)}"
        )

    def test_decision_function_returns_scores(self, model, sample_features):
        """decision_function() must return a float array of anomaly scores."""
        scores = model.decision_function(sample_features)
        assert isinstance(scores, np.ndarray)
        assert len(scores) == len(sample_features)
        assert scores.dtype in [np.float32, np.float64]

    def test_scores_are_finite(self, model, sample_features):
        """All anomaly scores must be finite (no NaN or inf)."""
        scores = model.decision_function(sample_features)
        assert np.all(np.isfinite(scores)), (
            f"Non-finite scores detected: {scores}"
        )

    def test_anomaly_scores_lower_than_normal(self, model, sample_features):
        """
        The anomalous row (row 1) should score lower than the normal row (row 0).
        Higher decision_function score = more normal.
        This validates the model's anomaly detection direction.
        """
        scores = model.decision_function(sample_features)
        normal_score  = scores[0]
        anomaly_score = scores[1]
        assert anomaly_score < normal_score, (
            f"Expected anomaly score ({anomaly_score:.4f}) < "
            f"normal score ({normal_score:.4f}). "
            "Model may not be detecting anomalies correctly."
        )


# ══════════════════════════════════════════════════════════════════════════════
# EDGE CASE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_single_row_input(self, model, feature_cols):
        """Model must handle a single-row DataFrame without errors."""
        single = pd.DataFrame([{col: 5.0 for col in feature_cols}])
        preds  = model.predict(single)
        scores = model.decision_function(single)
        assert len(preds) == 1
        assert len(scores) == 1

    def test_all_zero_input(self, model, feature_cols):
        """Model must handle all-zero feature input without crashing."""
        zeros  = pd.DataFrame([{col: 0.0 for col in feature_cols}])
        preds  = model.predict(zeros)
        scores = model.decision_function(zeros)
        assert len(preds) == 1
        assert np.isfinite(scores[0])

    def test_nan_values_handled(self, model, feature_cols):
        """
        Model must handle NaN values after imputation (as done in evaluate.py).
        NaN should be replaced with 0 before prediction.
        """
        nan_row = pd.DataFrame([{col: np.nan for col in feature_cols}])
        nan_row = nan_row.fillna(0.0)
        preds   = model.predict(nan_row)
        assert len(preds) == 1

    def test_inf_values_handled(self, model, feature_cols):
        """
        Model must handle inf values after replacement (as done in evaluate.py).
        """
        inf_row = pd.DataFrame([{col: np.inf for col in feature_cols}])
        inf_row = inf_row.replace([np.inf, -np.inf], 0.0)
        preds   = model.predict(inf_row)
        assert len(preds) == 1

    def test_large_batch_input(self, model, feature_cols):
        """Model must handle large batches efficiently."""
        large = pd.DataFrame([{col: float(i % 100) for col in feature_cols}
                               for i in range(1000)])
        preds  = model.predict(large)
        scores = model.decision_function(large)
        assert len(preds)  == 1000
        assert len(scores) == 1000


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TEST — FULL PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:

    def test_features_file_exists(self):
        """block_features.parquet must exist."""
        assert FEATURES_FILE.exists(), (
            f"Features file not found: {FEATURES_FILE}\n"
            "Run build_features.py first."
        )

    def test_features_file_loads(self):
        """block_features.parquet must load without error."""
        df = pd.read_parquet(FEATURES_FILE)
        assert len(df) > 0, "Feature file is empty."
        assert "block_id" in df.columns

    def test_model_scores_real_features(self, model, feature_cols):
        """
        Model must produce valid scores on the actual training features file.
        This is an end-to-end smoke test of the full pipeline.
        """
        if not FEATURES_FILE.exists():
            pytest.skip("block_features.parquet not found — skipping integration test.")

        df = pd.read_parquet(FEATURES_FILE)

        # Use only the columns the model was trained on
        missing = [c for c in feature_cols if c not in df.columns]
        for c in missing:
            df[c] = 0.0

        X = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)

        scores = model.decision_function(X)
        preds  = model.predict(X)

        assert len(scores) == len(df)
        assert np.all(np.isfinite(scores))
        assert set(preds).issubset({1, -1})

        n_anomalies = int((preds == -1).sum())
        anomaly_pct = 100 * n_anomalies / len(preds)
        print(f"\n  Scored {len(df)} blocks → {n_anomalies} anomalies ({anomaly_pct:.1f}%)")

        # Sanity check: anomaly rate should be between 0.1% and 20%
        assert 0.1 <= anomaly_pct <= 20.0, (
            f"Anomaly rate {anomaly_pct:.1f}% is outside expected range [0.1%, 20%]. "
            "Model may be misconfigured."
        )
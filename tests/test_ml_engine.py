"""Focused tests for synthetic data, artifact integrity, inference, and explanations."""

# Direct tests intentionally use concrete boundary values for readability.
# ruff: noqa: PLR2004, S105

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from app.services.explainability import ExplainabilityService
from app.services.ml_engine import MLEngine, MLPolicy, ModelBundle, ModelLoadError
from ml.generate_dataset import GeneratorConfig, generate

FEATURES = (
    "amount",
    "velocity_5m",
    "amount_to_average_ratio",
    "distance_from_home_km",
    "merchant_risk",
    "is_new_device",
)
BASELINES = {
    "amount": 500.0,
    "velocity_5m": 1,
    "amount_to_average_ratio": 1.0,
    "distance_from_home_km": 10.0,
    "merchant_risk": 0.1,
    "is_new_device": 0,
}


class FakeProbabilityModel:
    """Pickle-safe deterministic classifier used without external model training."""

    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        row = frame.iloc[0]
        risk = min(
            0.99,
            0.05
            + float(row["velocity_5m"]) * 0.08
            + float(row["amount_to_average_ratio"]) * 0.07
            + float(row["merchant_risk"]) * 0.25
            + float(row["is_new_device"]) * 0.15,
        )
        return np.array([[1 - risk, risk]])


class SlowProbabilityModel(FakeProbabilityModel):
    def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
        time.sleep(0.04)
        return super().predict_proba(frame)


def _features() -> dict[str, object]:
    return {
        "amount": 15_000.0,
        "velocity_5m": 7,
        "amount_to_average_ratio": 5.2,
        "distance_from_home_km": 900.0,
        "merchant_risk": 0.75,
        "is_new_device": 1,
    }


def _write_artifact(tmp_path: Path, model: object | None = None) -> tuple[Path, Path]:
    artifact = tmp_path / "fraud_model.joblib"
    metadata = tmp_path / "fraud_model.metadata.json"
    joblib.dump(
        {
            "pipeline": model or FakeProbabilityModel(),
            "model_version": "test-v1",
            "feature_schema_version": "1.0.0",
            "features": list(FEATURES),
            "baselines": BASELINES,
            "decision_threshold": 0.55,
        },
        artifact,
    )
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    metadata.write_text(json.dumps({"artifact_sha256": digest}), encoding="utf-8")
    return artifact, metadata


def test_synthetic_generator_is_reproducible_and_privacy_safe() -> None:
    config = GeneratorConfig(rows=1_000, seed=19, fraud_rate=0.05)
    first, second = generate(config), generate(config)

    pd.testing.assert_frame_equal(first, second)
    assert 0.02 <= first["is_fraud"].mean() <= 0.08
    assert first["customer_token"].str.fullmatch(r"[0-9a-f]{24}").all()
    assert not {"name", "email", "phone", "pan"} & set(first.columns)


def test_engine_validates_integrity_and_scores_high_risk_event(tmp_path: Path) -> None:
    artifact, metadata = _write_artifact(tmp_path)
    engine = MLEngine(MLPolicy(artifact_path=artifact, metadata_path=metadata))

    result = engine.score(_features())

    assert result.available is True
    assert result.score > 0.80
    assert result.version == "test-v1"
    assert "ML_HIGH_VELOCITY" in result.reason_codes
    assert "ML_GEO_ANOMALY" in result.reason_codes


def test_engine_rejects_tampered_artifact(tmp_path: Path) -> None:
    artifact, metadata = _write_artifact(tmp_path)
    with artifact.open("ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(ModelLoadError, match="SHA-256"):
        MLEngine(MLPolicy(artifact_path=artifact, metadata_path=metadata)).load()


@pytest.mark.asyncio
async def test_async_timeout_returns_degraded_component(tmp_path: Path) -> None:
    artifact, metadata = _write_artifact(tmp_path, SlowProbabilityModel())
    engine = MLEngine(MLPolicy(artifact_path=artifact, metadata_path=metadata, timeout_ms=10))

    result = await engine.score_async(_features())

    assert result.available is False
    assert result.error_code == "ML_TIMEOUT"


def test_explanation_is_ranked_and_bounded(tmp_path: Path) -> None:
    artifact, metadata = _write_artifact(tmp_path)
    bundle = MLEngine(MLPolicy(artifact_path=artifact, metadata_path=metadata)).load()
    explanation = ExplainabilityService(bundle, maximum_features=3).explain(_features())

    assert explanation.model_version == "test-v1"
    assert explanation.predicted_score > explanation.base_score
    assert len(explanation.contributions) == 3
    magnitudes = [abs(item.contribution) for item in explanation.contributions]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_explanation_redacts_identity_like_feature() -> None:
    class TokenAwareModel:
        def predict_proba(self, frame: pd.DataFrame) -> np.ndarray:
            risk = 0.8 if frame.iloc[0]["customer_token"] != "baseline" else 0.1
            return np.array([[1 - risk, risk]])

    bundle = ModelBundle(
        pipeline=TokenAwareModel(),
        model_version="privacy-test",
        feature_schema_version="1.0.0",
        features=("customer_token",),
        baselines={"customer_token": "baseline"},
        decision_threshold=0.5,
        artifact_sha256="0" * 64,
    )
    explanation = ExplainabilityService(bundle).explain({"customer_token": "secret-value"})

    assert explanation.contributions[0].display_value == "[REDACTED]"

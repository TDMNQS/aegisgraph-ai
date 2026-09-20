"""Integrity-checked, bounded-latency inference for the fraud model."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

import joblib
import pandas as pd

from app.services.risk_aggregator import ComponentScore

MINIMUM_TIMEOUT_MS = 10
MAX_STRING_FEATURE_LENGTH = 128
HIGH_VELOCITY_THRESHOLD = 5
AMOUNT_DEVIATION_THRESHOLD = 4.0
GEO_ANOMALY_THRESHOLD_KM = 700.0
HIGH_MERCHANT_RISK_THRESHOLD = 0.65


class ProbabilityModel(Protocol):
    def predict_proba(self, values: pd.DataFrame) -> Any: ...


class ModelLoadError(RuntimeError):
    """Raised when an artifact is absent, invalid, or fails integrity validation."""


class FeatureValidationError(ValueError):
    """Raised when online features do not conform to the trained schema."""


@dataclass(frozen=True, slots=True)
class ModelBundle:
    pipeline: ProbabilityModel
    model_version: str
    feature_schema_version: str
    features: tuple[str, ...]
    baselines: Mapping[str, object]
    decision_threshold: float
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class MLPolicy:
    artifact_path: Path = Path("artifacts/fraud_model.joblib")
    metadata_path: Path = Path("artifacts/fraud_model.metadata.json")
    expected_schema_version: str = "1.0.0"
    expected_sha256: str | None = None
    timeout_ms: int = 100
    maximum_concurrency: int = 8

    def __post_init__(self) -> None:
        if self.timeout_ms < MINIMUM_TIMEOUT_MS:
            raise ValueError("timeout_ms must be at least 10")
        if self.maximum_concurrency < 1:
            raise ValueError("maximum_concurrency must be positive")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class MLEngine:
    """Load a signed artifact once and expose safe sync/async scoring methods."""

    def __init__(self, policy: MLPolicy) -> None:
        self._policy = policy
        self._bundle: ModelBundle | None = None
        self._artifact_mtime_ns: int | None = None
        self._lock = RLock()
        self._semaphore = asyncio.Semaphore(policy.maximum_concurrency)

    @property
    def model_version(self) -> str | None:
        return self._bundle.model_version if self._bundle else None

    def load(self, *, force: bool = False) -> ModelBundle:
        """Load or atomically reload the model after validating all metadata."""
        artifact = self._policy.artifact_path
        metadata_path = self._policy.metadata_path
        if not artifact.is_file() or not metadata_path.is_file():
            raise ModelLoadError("model artifact or metadata file does not exist")
        mtime_ns = artifact.stat().st_mtime_ns
        with self._lock:
            if not force and self._bundle is not None and self._artifact_mtime_ns == mtime_ns:
                return self._bundle
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ModelLoadError("model metadata is not valid JSON") from exc
            actual_digest = _sha256(artifact)
            expected_digest = self._policy.expected_sha256 or metadata.get("artifact_sha256")
            if not isinstance(expected_digest, str) or actual_digest != expected_digest:
                raise ModelLoadError("model artifact SHA-256 does not match trusted metadata")
            try:
                raw = joblib.load(artifact)
                features = tuple(raw["features"])
                bundle = ModelBundle(
                    pipeline=raw["pipeline"],
                    model_version=str(raw["model_version"]),
                    feature_schema_version=str(raw["feature_schema_version"]),
                    features=features,
                    baselines=dict(raw["baselines"]),
                    decision_threshold=float(raw["decision_threshold"]),
                    artifact_sha256=actual_digest,
                )
            except Exception as exc:
                raise ModelLoadError("model artifact structure is invalid") from exc
            if bundle.feature_schema_version != self._policy.expected_schema_version:
                raise ModelLoadError("model feature schema is incompatible with this service")
            if not bundle.features or len(set(bundle.features)) != len(bundle.features):
                raise ModelLoadError("model feature list is empty or contains duplicates")
            if not 0 < bundle.decision_threshold < 1:
                raise ModelLoadError("model decision threshold is invalid")
            self._bundle, self._artifact_mtime_ns = bundle, mtime_ns
            return bundle

    def score(self, features: Mapping[str, object]) -> ComponentScore:
        """Score one transaction and return a hybrid-aggregator component."""
        started = time.perf_counter()
        bundle = self.load()
        row = self._frame(bundle, features)
        try:
            probability = float(bundle.pipeline.predict_proba(row)[0][1])
        except Exception as exc:
            raise RuntimeError("fraud model prediction failed") from exc
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise RuntimeError("fraud model returned an invalid probability")
        reasons = self._reason_codes(features, probability, bundle.decision_threshold)
        latency = (time.perf_counter() - started) * 1_000
        return ComponentScore(
            score=round(probability, 6),
            confidence=self._confidence(probability),
            reason_codes=reasons,
            version=bundle.model_version,
            latency_ms=round(latency, 3),
        )

    async def score_async(self, features: Mapping[str, object]) -> ComponentScore:
        """Bound concurrent predictions and fail safely when latency exceeds policy."""
        try:
            async with self._semaphore:
                return await asyncio.wait_for(
                    asyncio.to_thread(self.score, dict(features)),
                    timeout=self._policy.timeout_ms / 1_000,
                )
        except TimeoutError:
            return ComponentScore.unavailable("ML_TIMEOUT")
        except (ModelLoadError, FeatureValidationError, RuntimeError):
            return ComponentScore.unavailable("ML_UNAVAILABLE")

    @staticmethod
    def _frame(bundle: ModelBundle, supplied: Mapping[str, object]) -> pd.DataFrame:
        missing = [name for name in bundle.features if name not in supplied]
        if missing:
            raise FeatureValidationError(f"missing model features: {', '.join(missing)}")
        row: dict[str, object] = {}
        for name in bundle.features:
            value = supplied[name]
            if isinstance(value, float) and not math.isfinite(value):
                raise FeatureValidationError(f"feature {name} is not finite")
            if isinstance(value, str) and len(value) > MAX_STRING_FEATURE_LENGTH:
                raise FeatureValidationError(f"feature {name} exceeds 128 characters")
            row[name] = value
        return pd.DataFrame([row], columns=bundle.features)

    @staticmethod
    def _confidence(probability: float) -> float:
        # Probability distance from ambiguity, with a non-zero calibrated floor.
        return round(0.55 + 0.45 * abs(probability - 0.5) * 2, 6)

    @staticmethod
    def _reason_codes(
        features: Mapping[str, object], score: float, threshold: float
    ) -> tuple[str, ...]:
        if score < threshold:
            return ()
        rules: tuple[tuple[str, bool], ...] = (
            (
                "ML_HIGH_VELOCITY",
                float(features.get("velocity_5m", 0)) >= HIGH_VELOCITY_THRESHOLD,
            ),
            (
                "ML_AMOUNT_DEVIATION",
                float(features.get("amount_to_average_ratio", 0)) >= AMOUNT_DEVIATION_THRESHOLD,
            ),
            ("ML_NEW_DEVICE", bool(features.get("is_new_device", False))),
            (
                "ML_GEO_ANOMALY",
                float(features.get("distance_from_home_km", 0)) >= GEO_ANOMALY_THRESHOLD_KM,
            ),
            (
                "ML_MERCHANT_RISK",
                float(features.get("merchant_risk", 0)) >= HIGH_MERCHANT_RISK_THRESHOLD,
            ),
        )
        found = tuple(code for code, matched in rules if matched)
        return found or ("ML_ANOMALOUS_PATTERN",)

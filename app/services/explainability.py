"""Bounded, privacy-aware local explanations for AegisGraph fraud decisions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import pandas as pd

from app.services.ml_engine import ModelBundle

MAX_EXPLANATION_FEATURES = 20
MAX_DISPLAY_VALUE_LENGTH = 64


@dataclass(frozen=True, slots=True)
class FeatureContribution:
    feature: str
    contribution: float
    direction: str
    display_value: str


@dataclass(frozen=True, slots=True)
class PredictionExplanation:
    model_version: str
    base_score: float
    predicted_score: float
    contributions: tuple[FeatureContribution, ...]
    method: str = "baseline_occlusion"


class ExplainabilityService:
    """Explain a prediction by replacing one feature at a time with its baseline.

    This deterministic fallback works for every supported classifier and avoids
    returning raw identity tokens. SHAP can later be enabled for offline analysis,
    while this bounded method remains suitable for synchronous analyst responses.
    """

    SENSITIVE_FRAGMENTS = ("token", "email", "phone", "account", "ip", "customer")

    def __init__(self, bundle: ModelBundle, *, maximum_features: int = 8) -> None:
        if maximum_features < 1 or maximum_features > MAX_EXPLANATION_FEATURES:
            raise ValueError("maximum_features must be between 1 and 20")
        self._bundle = bundle
        self._maximum_features = maximum_features

    def explain(self, features: Mapping[str, object]) -> PredictionExplanation:
        missing = [name for name in self._bundle.features if name not in features]
        if missing:
            raise ValueError(f"missing explanation features: {', '.join(missing)}")
        observed = {name: features[name] for name in self._bundle.features}
        base = {name: self._bundle.baselines[name] for name in self._bundle.features}
        predicted_score = self._predict(observed)
        base_score = self._predict(base)
        contributions: list[FeatureContribution] = []
        for feature in self._bundle.features:
            occluded = dict(observed)
            occluded[feature] = base[feature]
            delta = predicted_score - self._predict(occluded)
            contributions.append(
                FeatureContribution(
                    feature=feature,
                    contribution=round(delta, 6),
                    direction="increases_risk" if delta >= 0 else "decreases_risk",
                    display_value=self._safe_value(feature, observed[feature]),
                )
            )
        ranked = sorted(contributions, key=lambda item: (-abs(item.contribution), item.feature))
        return PredictionExplanation(
            model_version=self._bundle.model_version,
            base_score=round(base_score, 6),
            predicted_score=round(predicted_score, 6),
            contributions=tuple(ranked[: self._maximum_features]),
        )

    def _predict(self, row: Mapping[str, object]) -> float:
        frame = pd.DataFrame([row], columns=self._bundle.features)
        return float(self._bundle.pipeline.predict_proba(frame)[0][1])

    @classmethod
    def _safe_value(cls, feature: str, value: object) -> str:
        if any(fragment in feature.casefold() for fragment in cls.SENSITIVE_FRAGMENTS):
            return "[REDACTED]"
        text = str(value)
        return (
            text
            if len(text) <= MAX_DISPLAY_VALUE_LENGTH
            else text[: MAX_DISPLAY_VALUE_LENGTH - 3] + "..."
        )

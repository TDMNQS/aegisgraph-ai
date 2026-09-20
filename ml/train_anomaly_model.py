"""Train, evaluate, and sign a reproducible AegisGraph fraud classifier."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

NUMERIC_FEATURES: Final = [
    "amount",
    "hour_of_day",
    "day_of_week",
    "account_age_days",
    "device_age_hours",
    "velocity_5m",
    "velocity_1h",
    "distance_from_home_km",
    "merchant_risk",
    "customer_avg_amount",
    "amount_to_average_ratio",
    "failed_attempts_24h",
    "is_new_device",
    "is_foreign_transaction",
    "is_night_transaction",
]
CATEGORICAL_FEATURES: Final = ["channel", "country_code", "merchant_category_code"]
FEATURES: Final = NUMERIC_FEATURES + CATEGORICAL_FEATURES
TARGET: Final = "is_fraud"
SCHEMA_VERSION: Final = "1.0.0"
BINARY_CLASS_COUNT: Final = 2
MINIMUM_TRAIN_ROWS: Final = 500
MINIMUM_TEST_ROWS: Final = 200


def _estimator(kind: str, seed: int) -> Any:
    if kind == "logistic":
        return LogisticRegression(max_iter=1_000, class_weight="balanced", random_state=seed)
    if kind == "random_forest":
        return RandomForestClassifier(
            n_estimators=350,
            max_depth=14,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=seed,
        )
    if kind == "xgboost":
        try:
            xgboost = importlib.import_module("xgboost")
        except ImportError as exc:
            raise RuntimeError(
                "install the ml extra to train XGBoost: pip install -e '.[ml]'"
            ) from exc
        return xgboost.XGBClassifier(
            n_estimators=450,
            max_depth=6,
            learning_rate=0.045,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_weight=4,
            reg_lambda=2.0,
            eval_metric="logloss",
            random_state=seed,
            n_jobs=-1,
        )
    raise ValueError("model must be logistic, random_forest, or xgboost")


def build_pipeline(kind: str, seed: int) -> Pipeline:
    numeric = Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())])
    categorical = Pipeline(
        [
            ("impute", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=5)),
        ]
    )
    return Pipeline(
        [
            (
                "features",
                ColumnTransformer(
                    [
                        ("numeric", numeric, NUMERIC_FEATURES),
                        ("categorical", categorical, CATEGORICAL_FEATURES),
                    ]
                ),
            ),
            ("classifier", _estimator(kind, seed)),
        ]
    )


def load_dataset(path: Path) -> pd.DataFrame:
    frame = pd.read_parquet(path) if path.suffix.lower() == ".parquet" else pd.read_csv(path)
    missing = sorted({*FEATURES, TARGET, "occurred_at"} - set(frame.columns))
    if missing:
        raise ValueError(f"dataset is missing required columns: {', '.join(missing)}")
    frame = frame.copy()
    frame["occurred_at"] = pd.to_datetime(frame["occurred_at"], utc=True, errors="raise")
    if frame[TARGET].nunique() != BINARY_CLASS_COUNT:
        raise ValueError("dataset must contain both fraud and legitimate labels")
    return frame.sort_values("occurred_at", kind="stable").reset_index(drop=True)


def choose_threshold(labels: np.ndarray, probabilities: np.ndarray, minimum_recall: float) -> float:
    """Select the highest-precision threshold satisfying the recall constraint."""
    candidates = np.linspace(0.05, 0.95, 181)
    best = (0.5, -1.0)
    for threshold in candidates:
        prediction = probabilities >= threshold
        precision, recall, _, _ = precision_recall_fscore_support(
            labels, prediction, average="binary", zero_division=0
        )
        if recall >= minimum_recall and precision > best[1]:
            best = (float(threshold), float(precision))
    return best[0]


def train(
    data: Path, artifact: Path, metadata_path: Path, model_kind: str, seed: int
) -> dict[str, Any]:
    frame = load_dataset(data)
    split = int(len(frame) * 0.80)
    if split < MINIMUM_TRAIN_ROWS or len(frame) - split < MINIMUM_TEST_ROWS:
        raise ValueError("dataset is too small for a reliable temporal holdout")
    train_frame, test_frame = frame.iloc[:split], frame.iloc[split:]
    pipeline = build_pipeline(model_kind, seed)
    pipeline.fit(train_frame[FEATURES], train_frame[TARGET])
    probabilities = np.asarray(pipeline.predict_proba(test_frame[FEATURES]))[:, 1]
    labels = test_frame[TARGET].to_numpy(dtype=int)
    threshold = choose_threshold(labels, probabilities, minimum_recall=0.70)
    predicted = probabilities >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted, average="binary", zero_division=0
    )
    version = datetime.now(UTC).strftime("fraud-%Y%m%dT%H%M%SZ")
    baselines = {
        **{name: float(train_frame[name].median()) for name in NUMERIC_FEATURES},
        **{name: str(train_frame[name].mode(dropna=True).iloc[0]) for name in CATEGORICAL_FEATURES},
    }
    payload = {
        "pipeline": pipeline,
        "model_version": version,
        "feature_schema_version": SCHEMA_VERSION,
        "features": FEATURES,
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "baselines": baselines,
        "decision_threshold": threshold,
    }
    artifact.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, artifact, compress=3)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    metadata = {
        "model_version": version,
        "model_kind": model_kind,
        "feature_schema_version": SCHEMA_VERSION,
        "artifact_sha256": digest,
        "trained_at": datetime.now(UTC).isoformat(),
        "training_rows": len(train_frame),
        "test_rows": len(test_frame),
        "test_period": {
            "start": test_frame["occurred_at"].min().isoformat(),
            "end": test_frame["occurred_at"].max().isoformat(),
        },
        "fraud_rate_train": float(train_frame[TARGET].mean()),
        "fraud_rate_test": float(test_frame[TARGET].mean()),
        "decision_threshold": threshold,
        "metrics": {
            "roc_auc": float(roc_auc_score(labels, probabilities)),
            "average_precision": float(average_precision_score(labels, probabilities)),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        },
        "runtime": {"python": platform.python_version(), "scikit_learn": sklearn.__version__},
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/synthetic_transactions.csv"))
    parser.add_argument("--artifact", type=Path, default=Path("artifacts/fraud_model.joblib"))
    parser.add_argument(
        "--metadata", type=Path, default=Path("artifacts/fraud_model.metadata.json")
    )
    parser.add_argument(
        "--model", choices=["logistic", "random_forest", "xgboost"], default="xgboost"
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    result = train(args.data, args.artifact, args.metadata, args.model, args.seed)
    sys.stdout.write(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()

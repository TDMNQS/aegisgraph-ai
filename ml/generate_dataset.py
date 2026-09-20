"""Generate privacy-safe synthetic card-payment data with explainable fraud labels.

The generator intentionally creates correlated fraud patterns instead of assigning
labels randomly. It never produces names, PANs, email addresses, phone numbers, or
other direct identifiers. Stable opaque tokens are safe for local graph experiments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import numpy as np
import pandas as pd

COUNTRIES: Final = np.array(["IN", "US", "GB", "AE", "SG", "DE", "BR", "NG"])
CHANNELS: Final = np.array(["ecommerce", "pos", "mobile", "atm"])
MCCS: Final = np.array(["5411", "5812", "5999", "5732", "7995", "4829", "6011"])
FEATURE_SCHEMA_VERSION: Final = "1.0.0"
MINIMUM_ROWS: Final = 1_000
MINIMUM_FRAUD_RATE: Final = 0.005
MAXIMUM_FRAUD_RATE: Final = 0.25
NEW_DEVICE_HOURS: Final = 24
NIGHT_END_HOUR: Final = 4
NIGHT_START_HOUR: Final = 23
HIGH_VELOCITY: Final = 5
HIGH_AMOUNT_RATIO: Final = 4.0
LONG_DISTANCE_KM: Final = 700.0
MANY_FAILED_ATTEMPTS: Final = 3


@dataclass(frozen=True, slots=True)
class GeneratorConfig:
    """Validated controls for deterministic data creation."""

    rows: int = 50_000
    seed: int = 42
    fraud_rate: float = 0.035
    start: datetime = datetime(2025, 1, 1, tzinfo=UTC)

    def __post_init__(self) -> None:
        if self.rows < MINIMUM_ROWS:
            raise ValueError("rows must be at least 1,000")
        if not MINIMUM_FRAUD_RATE <= self.fraud_rate <= MAXIMUM_FRAUD_RATE:
            raise ValueError("fraud_rate must be between 0.5% and 25%")
        if self.start.tzinfo is None:
            raise ValueError("start must be timezone-aware")


def _token(namespace: str, value: int) -> str:
    return hashlib.sha256(f"aegisgraph-synthetic:{namespace}:{value}".encode()).hexdigest()[:24]


def generate(config: GeneratorConfig) -> pd.DataFrame:
    """Return a deterministic dataset containing normal and patterned fraud events."""

    rng = np.random.default_rng(config.seed)
    n = config.rows
    customer_index = rng.integers(0, max(500, n // 12), n)
    device_index = rng.integers(0, max(350, n // 20), n)
    merchant_index = rng.integers(0, 800, n)
    elapsed_seconds = np.sort(rng.integers(0, 180 * 86_400, n))
    occurred_at = pd.to_datetime(
        [config.start + timedelta(seconds=int(value)) for value in elapsed_seconds], utc=True
    )

    channel = rng.choice(CHANNELS, n, p=[0.46, 0.31, 0.16, 0.07])
    country = rng.choice(COUNTRIES, n, p=[0.67, 0.08, 0.06, 0.06, 0.05, 0.03, 0.03, 0.02])
    mcc = rng.choice(MCCS, n, p=[0.26, 0.20, 0.16, 0.13, 0.08, 0.09, 0.08])
    amount = np.clip(rng.lognormal(mean=5.35, sigma=1.15, size=n), 5, 250_000)
    hour = occurred_at.hour.to_numpy()
    account_age_days = np.maximum(0, rng.gamma(3.2, 180, n)).astype(int)
    velocity_5m = np.clip(rng.poisson(1.1, n), 0, 15)
    velocity_1h = velocity_5m + np.clip(rng.poisson(2.8, n), 0, 35)
    distance_from_home_km = np.clip(rng.exponential(35, n), 0, 8_000)
    device_age_hours = np.clip(rng.lognormal(6.0, 1.8, n), 0, 50_000)
    merchant_risk = np.clip(rng.beta(1.4, 8.5, n), 0, 1)
    customer_avg_amount = np.clip(amount * rng.lognormal(0, 0.6, n), 5, 100_000)
    amount_ratio = np.clip(amount / customer_avg_amount, 0.01, 50)
    failed_attempts_24h = np.clip(rng.poisson(0.22, n), 0, 20)
    is_new_device = device_age_hours < NEW_DEVICE_HOURS
    is_foreign = country != "IN"
    is_night = (hour <= NIGHT_END_HOUR) | (hour >= NIGHT_START_HOUR)

    # Latent risk encodes recognizable attack patterns while retaining noisy overlap.
    latent = (
        -5.0
        + 1.45 * (velocity_5m >= HIGH_VELOCITY)
        + 1.15 * (amount_ratio >= HIGH_AMOUNT_RATIO)
        + 0.95 * is_new_device
        + 0.80 * is_foreign
        + 0.65 * is_night
        + 1.25 * (distance_from_home_km >= LONG_DISTANCE_KM)
        + 1.10 * (failed_attempts_24h >= MANY_FAILED_ATTEMPTS)
        + 1.35 * (mcc == "7995")
        + 1.15 * (mcc == "4829")
        + 2.2 * merchant_risk
        + rng.normal(0, 0.65, n)
    )
    probability = 1 / (1 + np.exp(-latent))
    # Scale probabilities to the requested prevalence without destroying rank/order.
    low, high = 0.05, 20.0
    for _ in range(40):
        scale = (low + high) / 2
        observed = np.mean(np.clip(probability * scale, 0, 0.98))
        if observed < config.fraud_rate:
            low = scale
        else:
            high = scale
    probability = np.clip(probability * ((low + high) / 2), 0, 0.98)
    is_fraud = rng.binomial(1, probability).astype(np.int8)

    frame = pd.DataFrame(
        {
            "transaction_id": [f"syn_{i:010d}" for i in range(n)],
            "occurred_at": occurred_at,
            "customer_token": [_token("customer", int(i)) for i in customer_index],
            "device_token": [_token("device", int(i)) for i in device_index],
            "merchant_token": [_token("merchant", int(i)) for i in merchant_index],
            "amount": np.round(amount, 2),
            "currency": "INR",
            "channel": channel,
            "country_code": country,
            "merchant_category_code": mcc,
            "hour_of_day": hour,
            "day_of_week": occurred_at.dayofweek.to_numpy(),
            "account_age_days": account_age_days,
            "device_age_hours": np.round(device_age_hours, 2),
            "velocity_5m": velocity_5m,
            "velocity_1h": velocity_1h,
            "distance_from_home_km": np.round(distance_from_home_km, 2),
            "merchant_risk": np.round(merchant_risk, 6),
            "customer_avg_amount": np.round(customer_avg_amount, 2),
            "amount_to_average_ratio": np.round(amount_ratio, 4),
            "failed_attempts_24h": failed_attempts_24h,
            "is_new_device": is_new_device.astype(np.int8),
            "is_foreign_transaction": is_foreign.astype(np.int8),
            "is_night_transaction": is_night.astype(np.int8),
            "is_fraud": is_fraud,
        }
    )
    return frame.sort_values("occurred_at", kind="stable").reset_index(drop=True)


def write_dataset(frame: pd.DataFrame, output: Path) -> None:
    """Write CSV or Parquet plus a small provenance manifest."""

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix.lower() == ".parquet":
        frame.to_parquet(output, index=False)
    elif output.suffix.lower() == ".csv":
        frame.to_csv(output, index=False)
    else:
        raise ValueError("output extension must be .csv or .parquet")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "rows": len(frame),
        "fraud_rows": int(frame["is_fraud"].sum()),
        "fraud_rate": round(float(frame["is_fraud"].mean()), 6),
        "sha256": digest,
        "synthetic_only": True,
        "generated_at": datetime.now(UTC).isoformat(),
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=50_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fraud-rate", type=float, default=0.035)
    parser.add_argument("--output", type=Path, default=Path("data/synthetic_transactions.csv"))
    args = parser.parse_args()
    frame = generate(GeneratorConfig(rows=args.rows, seed=args.seed, fraud_rate=args.fraud_rate))
    write_dataset(frame, args.output)
    sys.stdout.write(f"wrote {len(frame):,} synthetic transactions to {args.output}\n")


if __name__ == "__main__":
    main()

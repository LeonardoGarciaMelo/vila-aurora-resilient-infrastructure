"""RT-16: trains IsolationForest on synthetic normal telemetry, then measures it on injected attacks."""
import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from features import FEATURES, window_features

SEED_TRAIN, SEED_VALIDATION, SEED_TEST = 712, 1, 2026
WINDOW_POINTS = 60  # 5 minutes at one reading every 5 seconds
TRAIN_DAYS, TEST_DAYS = 14, 7
WINDOWS_PER_DAY = 288
CONTAMINATION_GRID = [0.002, 0.005, 0.01, 0.02, 0.05]
ATTACKS_PER_KIND = 60
MODEL_PATH = Path("/tmp/model.joblib")
RESULTS = Path("/results/ai_anomaly_metrics.json")


def normal_window(rng: np.random.Generator, hour: float, level_start: float):
    """Normal behaviour: the pump only runs in a morning cycle, the chamber holds around 4.5 C."""
    pump_on = 6 <= hour < 7
    drift = -0.5 if pump_on else 0.02
    level = level_start + drift * np.arange(WINDOW_POINTS) + rng.normal(0, 0.1, WINDOW_POINTS)
    pump = np.full(WINDOW_POINTS, float(pump_on))
    temp = 4.5 + rng.normal(0, 0.1, WINDOW_POINTS)
    return level, pump, temp


def night_drain(rng, hour, level_start):
    level = level_start - 0.5 * np.arange(WINDOW_POINTS) + rng.normal(0, 0.1, WINDOW_POINTS)
    return level, np.ones(WINDOW_POINTS), 4.5 + rng.normal(0, 0.1, WINDOW_POINTS)


def temperature_ramp(rng, hour, level_start):
    level = level_start + 0.02 * np.arange(WINDOW_POINTS) + rng.normal(0, 0.1, WINDOW_POINTS)
    temp = 4.5 + np.linspace(0, rng.uniform(1.5, 4), WINDOW_POINTS) + rng.normal(0, 0.1, WINDOW_POINTS)
    return level, np.zeros(WINDOW_POINTS), temp


def frozen_readings(rng, hour, level_start):
    level = np.full(WINDOW_POINTS, level_start)
    return level, np.zeros(WINDOW_POINTS), np.full(WINDOW_POINTS, 4.5)


def build_normal(rng, windows: int):
    rows, level = [], 70.0
    for i in range(windows):
        hour = (i % WINDOWS_PER_DAY) * 24 / WINDOWS_PER_DAY
        lv, pump, temp = normal_window(rng, hour, level)
        level = float(np.clip(lv[-1], 30, 95))
        rows.append(window_features(lv, pump, temp, hour))
    return np.array(rows)


def build_attacks(rng):
    injected, kinds = [], []
    for name, generator, hours in [("night_drain", night_drain, (1, 5)), ("temperature_ramp", temperature_ramp, (0, 24)),
                                   ("frozen_readings", frozen_readings, (0, 24))]:
        for _ in range(ATTACKS_PER_KIND):
            hour = rng.uniform(*hours)
            lv, pump, temp = generator(rng, hour, rng.uniform(40, 90))
            injected.append(window_features(lv, pump, temp, hour))
            kinds.append(name)
    return np.array(injected), kinds


def evaluate(model, normal, injected):
    x = np.vstack([normal, injected])
    y_true = np.array([0] * len(normal) + [1] * len(injected))
    y_pred = (model.predict(x) == -1).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {"precision": round(float(precision), 4), "recall": round(float(recall), 4), "f1": round(float(f1), 4),
            "false_positive_rate": round(float(fp / (fp + tn)), 4),
            "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}, "windows": len(x), "anomalies": int(y_true.sum())}


def main() -> None:
    train = build_normal(np.random.default_rng(SEED_TRAIN), TRAIN_DAYS * WINDOWS_PER_DAY)

    # The threshold is chosen on validation data; the test seed is only used for the final numbers.
    val_rng = np.random.default_rng(SEED_VALIDATION)
    val_normal = build_normal(val_rng, TEST_DAYS * WINDOWS_PER_DAY)
    val_attacks, _ = build_attacks(val_rng)
    candidates = {}
    for contamination in CONTAMINATION_GRID:
        model = IsolationForest(n_estimators=300, contamination=contamination, random_state=SEED_TRAIN).fit(train)
        candidates[contamination] = evaluate(model, val_normal, val_attacks)
    best = max(candidates, key=lambda c: candidates[c]["f1"])

    model = IsolationForest(n_estimators=300, contamination=best, random_state=SEED_TRAIN).fit(train)
    test_rng = np.random.default_rng(SEED_TEST)
    test_normal = build_normal(test_rng, TEST_DAYS * WINDOWS_PER_DAY)
    test_attacks, kinds = build_attacks(test_rng)
    test = evaluate(model, test_normal, test_attacks)
    per_kind = {k: round(float((model.predict(test_attacks[[i for i, n in enumerate(kinds) if n == k]]) == -1).mean()), 3)
                for k in sorted(set(kinds))}
    metrics = {
        "generated_at": datetime.now().isoformat(), "model": "IsolationForest", "features": FEATURES,
        "train_windows": len(train), "train_days_synthetic": TRAIN_DAYS, "chosen_contamination": best,
        "validation_by_contamination": {str(k): {"f1": v["f1"], "recall": v["recall"], "fpr": v["false_positive_rate"]} for k, v in candidates.items()},
        "test": test, "recall_per_attack": per_kind,
        "seeds": {"train": SEED_TRAIN, "validation": SEED_VALIDATION, "test": SEED_TEST},
        "caveat": "Measured on synthetic data generated by the team; expect lower performance on real telemetry.",
    }
    joblib.dump(model, MODEL_PATH)
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2), flush=True)


if __name__ == "__main__":
    main()

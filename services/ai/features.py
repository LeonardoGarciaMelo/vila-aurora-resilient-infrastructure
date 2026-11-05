"""Feature extraction shared by offline evaluation and the live detector (5-minute windows)."""
import math

import numpy as np

FEATURES = ["level_delta", "level_residual_std", "pump_ratio", "temp_mean", "temp_slope", "temp_residual_std", "hour_sin", "hour_cos"]


def residual_std(series: np.ndarray) -> float:
    """Spread around the trend: near zero when a sensor is frozen, whatever the value it is stuck at."""
    x = np.arange(len(series))
    slope, intercept = np.polyfit(x, series, 1)
    return float((series - (slope * x + intercept)).std())


def window_features(level: np.ndarray, pump: np.ndarray, temp: np.ndarray, hour: float) -> list[float]:
    x = np.arange(len(temp))
    return [
        float(level[-1] - level[0]),
        residual_std(level),
        float(pump.mean()),
        float(temp.mean()),
        float(np.polyfit(x, temp, 1)[0]),
        residual_std(temp),
        math.sin(2 * math.pi * hour / 24),
        math.cos(2 * math.pi * hour / 24),
    ]

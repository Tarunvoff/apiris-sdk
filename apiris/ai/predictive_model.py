from __future__ import annotations

import math
from typing import List, Dict


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


def predict_probability(model: Dict[str, List[float]], row: List[float]) -> float:
    mean = model.get("mean", [])
    std = model.get("std", [])
    weights = model.get("weights", [])
    standardized = [
        (row[idx] - mean[idx]) / (std[idx] or 1) if idx < len(mean) else row[idx]
        for idx in range(len(row))
    ]
    z = weights[0] if weights else 0.0
    for idx, value in enumerate(standardized):
        if idx + 1 < len(weights):
            z += weights[idx + 1] * value
    return _sigmoid(z)

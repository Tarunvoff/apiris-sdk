from __future__ import annotations

from typing import Dict, List

from .predictive_model import predict_probability


def predict_tradeoff(models: Dict[str, Dict], row: List[float]) -> Dict[str, object]:
    scores: Dict[str, float] = {}
    for tradeoff, model in models.items():
        scores[tradeoff] = predict_probability(model, row)
    entries = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    if not entries:
        return {"tradeoff": "none", "confidence": 0.0, "scores": scores}
    return {"tradeoff": entries[0][0], "confidence": entries[0][1], "scores": scores}


def top_contributors(model: Dict[str, List[float]], feature_names: List[str], row: List[float], count: int = 3) -> List[Dict[str, float]]:
    weights = model.get("weights", [])
    contributions = []
    for idx, name in enumerate(feature_names):
        weight = weights[idx + 1] if idx + 1 < len(weights) else 0
        value = row[idx] if idx < len(row) else 0
        contributions.append({"feature": name, "weight": weight, "value": value, "impact": abs(weight * value)})
    return sorted(contributions, key=lambda item: item["impact"], reverse=True)[:count]

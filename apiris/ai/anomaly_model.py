from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional

from .loader import load_json


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _extract_schema_paths(value: Any, prefix: str = "", depth: int = 0, max_depth: int = 6, paths: Optional[set] = None) -> set:
    if paths is None:
        paths = set()
    if depth > max_depth:
        return paths
    if isinstance(value, list):
        array_prefix = f"{prefix}[]" if prefix else "[]"
        paths.add(array_prefix)
        if value:
            _extract_schema_paths(value[0], array_prefix, depth + 1, max_depth, paths)
        return paths
    if isinstance(value, dict):
        for key, val in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            paths.add(next_prefix)
            _extract_schema_paths(val, next_prefix, depth + 1, max_depth, paths)
    return paths


def _collect_stats(value: Any, depth: int = 0, stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    current = stats or {
        "field_count": 0,
        "max_depth": 0,
        "array_count": 0,
        "null_count": 0,
        "value_count": 0,
        "numeric_values": [],
    }
    if isinstance(value, list):
        current["array_count"] += 1
        current["max_depth"] = max(current["max_depth"], depth)
        for item in value:
            _collect_stats(item, depth + 1, current)
        return current
    if isinstance(value, dict):
        current["max_depth"] = max(current["max_depth"], depth)
        for _, val in value.items():
            current["field_count"] += 1
            _collect_stats(val, depth + 1, current)
        return current

    current["value_count"] += 1
    if value is None:
        current["null_count"] += 1
    if isinstance(value, (int, float)) and math.isfinite(value):
        current["numeric_values"].append(float(value))
    return current


def _numeric_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return {
        "mean": mean,
        "std": math.sqrt(variance),
        "min": min(values),
        "max": max(values),
    }


def _compute_feature_vector(parsed: Any, context: Dict[str, Any]) -> Dict[str, Any]:
    schema_paths = sorted(_extract_schema_paths(parsed)) if parsed is not None else []
    schema_hash = _hash_text("|".join(schema_paths)) if schema_paths else None
    stats = _collect_stats(parsed)
    numeric = _numeric_stats(stats["numeric_values"])

    core_fields = context.get("core_fields") or []
    missing_core = 0
    if core_fields and schema_paths:
        path_set = set(schema_paths)
        for field in core_fields:
            if field not in path_set:
                missing_core += 1

    response_hash = context.get("response_hash")
    previous_hash = context.get("last_response_hash")
    repeat_count = (context.get("repeat_count") or 0) + 1 if previous_hash and response_hash == previous_hash else 0
    time_since_last = -1
    if response_hash and context.get("last_response_timestamp") and response_hash == previous_hash:
        time_since_last = (context.get("now") - context.get("last_response_timestamp")) / 1000

    numeric_jump = 0
    if context.get("last_numeric_mean") is not None:
        numeric_jump = abs(numeric["mean"] - context.get("last_numeric_mean"))

    return {
        "schemaHash": schema_hash,
        "responseHash": response_hash,
        "featureMap": {
            "field_count": stats["field_count"],
            "max_depth": stats["max_depth"],
            "array_count": stats["array_count"],
            "null_ratio": (stats["null_count"] / stats["value_count"]) if stats["value_count"] else 0,
            "numeric_mean": numeric["mean"],
            "numeric_std": numeric["std"],
            "numeric_min": numeric["min"],
            "numeric_max": numeric["max"],
            "numeric_jump": numeric_jump,
            "missing_core_ratio": (missing_core / len(core_fields)) if core_fields else 0,
            "repeat_count": repeat_count,
            "time_since_identical": time_since_last,
        },
    }


def _harmonic(n: int) -> float:
    return sum(1.0 / i for i in range(1, n + 1))


def _c_factor(n: int) -> float:
    if n <= 1:
        return 0.0
    return 2.0 * _harmonic(n - 1) - (2.0 * (n - 1)) / n


def _path_length(row: List[float], node: Dict[str, Any], depth: int) -> float:
    if node.get("leaf"):
        return depth + _c_factor(node.get("size", 1))
    feature = node.get("feature")
    split = node.get("split")
    if row[feature] <= split:
        return _path_length(row, node.get("left"), depth + 1)
    return _path_length(row, node.get("right"), depth + 1)


def score_isolation_forest(row: List[float], forest: Dict[str, Any]) -> float:
    lengths = [_path_length(row, tree, 0) for tree in forest.get("trees", [])]
    if not lengths:
        return 0.0
    avg = sum(lengths) / len(lengths)
    return math.pow(2, -avg / _c_factor(forest.get("sampleSize", 1)))


class AnomalyScorer:
    def __init__(self, model_path: str, soft_threshold: float, strong_threshold: float) -> None:
        self.model = load_json(model_path) or {}
        self.feature_names = self.model.get("featureNames") or []
        self.models = self.model.get("models") or {}
        self.soft_threshold = soft_threshold
        self.strong_threshold = strong_threshold

    def score(self, api: str, parsed: Any, response_text: Optional[str], runtime_state: Dict[str, Dict[str, Any]], now_ms: int) -> Optional[Dict[str, Any]]:
        api_model = self.models.get(api)
        if not api_model:
            return None

        if api not in runtime_state:
            runtime_state[api] = {
                "last_response_hash": None,
                "last_response_timestamp": None,
                "last_numeric_mean": None,
                "repeat_count": 0,
            }

        response_hash = _hash_text(response_text) if response_text else None
        state = runtime_state[api]
        feature_data = _compute_feature_vector(parsed, {
            "core_fields": api_model.get("coreFields") or [],
            "response_hash": response_hash,
            "last_response_hash": state.get("last_response_hash"),
            "last_response_timestamp": state.get("last_response_timestamp"),
            "last_numeric_mean": state.get("last_numeric_mean"),
            "repeat_count": state.get("repeat_count"),
            "now": now_ms,
        })

        row = [feature_data["featureMap"].get(name, 0) for name in self.feature_names]
        mean = api_model.get("mean") or []
        std = api_model.get("std") or []
        standardized = [
            (row[idx] - mean[idx]) / (std[idx] or 1) if idx < len(mean) else row[idx]
            for idx in range(len(row))
        ]

        anomaly_score = score_isolation_forest(standardized, api_model.get("forest") or {})
        anomaly_flag = "strong" if anomaly_score >= self.strong_threshold else "soft" if anomaly_score >= self.soft_threshold else "none"

        top_features = []
        for idx, name in enumerate(self.feature_names):
            value = feature_data["featureMap"].get(name, 0)
            z = (value - mean[idx]) / (std[idx] or 1) if idx < len(mean) else 0
            top_features.append({"feature": name, "value": value, "z": abs(z)})
        top_features = sorted(top_features, key=lambda item: item["z"], reverse=True)[:3]

        if response_hash and response_hash == state.get("last_response_hash"):
            state["repeat_count"] += 1
        else:
            state["repeat_count"] = 0
        state["last_response_hash"] = response_hash
        state["last_response_timestamp"] = now_ms
        state["last_numeric_mean"] = feature_data["featureMap"].get("numeric_mean", 0)

        return {
            "anomalyScore": anomaly_score,
            "anomalyFlag": anomaly_flag,
            "schemaHash": feature_data.get("schemaHash"),
            "responseHash": response_hash,
            "topFeatures": top_features,
            "features": feature_data.get("featureMap"),
        }

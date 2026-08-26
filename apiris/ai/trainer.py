"""
Per-API Anomaly Baseline Trainer for Apiris SDK
"""

from __future__ import annotations

import datetime
import json
import math
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from apiris.ai.anomaly_model import _collect_stats, _compute_feature_vector, _extract_schema_paths, _numeric_stats


def _build_simple_tree(features: List[List[float]], max_depth: int = 6, depth: int = 0) -> Dict[str, Any]:
    n_samples = len(features)
    if depth >= max_depth or n_samples <= 4:
        return {"leaf": True, "size": n_samples}

    n_features = len(features[0])
    feat_idx = random.randint(0, n_features - 1)
    col_vals = [row[feat_idx] for row in features]
    min_v, max_v = min(col_vals), max(col_vals)
    if math.isclose(min_v, max_v):
        return {"leaf": True, "size": n_samples}

    split = random.uniform(min_v, max_v)
    left_samples = [row for row in features if row[feat_idx] < split]
    right_samples = [row for row in features if row[feat_idx] >= split]

    if not left_samples or not right_samples:
        return {"leaf": True, "size": n_samples}

    return {
        "leaf": False,
        "feature": feat_idx,
        "split": round(split, 4),
        "left": _build_simple_tree(left_samples, max_depth, depth + 1),
        "right": _build_simple_tree(right_samples, max_depth, depth + 1),
    }


def train_per_api_baseline(
    api_name: str,
    samples_path: Path | str,
    model_json_path: Optional[Path | str] = None,
    num_trees: int = 25,
) -> Dict[str, Any]:
    path = Path(samples_path)
    if not path.exists():
        raise FileNotFoundError(f"Samples file not found: {path}")

    # Load samples (support both JSON array and JSONL lines)
    raw_samples: List[Any] = []
    content = path.read_text(encoding="utf-8").strip()
    if content.startswith("["):
        raw_samples = json.loads(content)
    else:
        for line in content.splitlines():
            line = line.strip()
            if line:
                raw_samples.append(json.loads(line))

    if not raw_samples:
        raise ValueError(f"No samples found in {path}")

    # Extract schema paths & feature vectors
    all_schema_paths: List[set] = []
    feature_vectors: List[List[float]] = []

    for item in raw_samples:
        parsed_body = item
        if isinstance(item, dict) and "body" in item and isinstance(item["body"], (str, dict, list)):
            if isinstance(item["body"], str):
                try:
                    parsed_body = json.loads(item["body"])
                except Exception:
                    parsed_body = item
            else:
                parsed_body = item["body"]

        paths = _extract_schema_paths(parsed_body)
        all_schema_paths.append(paths)

        fvec_dict = _compute_feature_vector(parsed_body, {})
        fmap = fvec_dict["featureMap"]
        ordered_vec = [
            float(fmap["field_count"]),
            float(fmap["max_depth"]),
            float(fmap["array_count"]),
            float(fmap["null_ratio"]),
            float(fmap["numeric_mean"]),
            float(fmap["numeric_std"]),
            float(fmap["numeric_min"]),
            float(fmap["numeric_max"]),
            float(fmap["numeric_jump"]),
            float(fmap["missing_core_ratio"]),
            float(fmap["repeat_count"]),
            float(fmap["time_since_identical"]),
        ]
        feature_vectors.append(ordered_vec)

    n_samples = len(feature_vectors)
    n_features = 12

    # Identify coreFields (fields in >= 90% of samples)
    path_counts: Dict[str, int] = {}
    for p_set in all_schema_paths:
        for p in p_set:
            path_counts[p] = path_counts.get(p, 0) + 1

    core_fields = [p for p, cnt in path_counts.items() if (cnt / n_samples) >= 0.90]

    # Compute empirical mean and std
    means = [0.0] * n_features
    for vec in feature_vectors:
        for i in range(n_features):
            means[i] += vec[i]
    means = [round(m / n_samples, 4) for m in means]

    stds = [0.0] * n_features
    for vec in feature_vectors:
        for i in range(n_features):
            stds[i] += (vec[i] - means[i]) ** 2
    stds = [round(max(0.1, math.sqrt(s / n_samples)), 4) for s in stds]

    # Standardize features for forest construction
    std_vectors: List[List[float]] = []
    for vec in feature_vectors:
        std_vec = [(vec[i] - means[i]) / stds[i] for i in range(n_features)]
        std_vectors.append(std_vec)

    # Build Isolation Forest trees
    trees = [_build_simple_tree(std_vectors, max_depth=6) for _ in range(num_trees)]

    trained_model = {
        "sampleCount": n_samples,
        "coreFields": sorted(core_fields),
        "mean": means,
        "std": stds,
        "forest": {
            "sampleSize": min(n_samples, 128),
            "trees": trees,
        },
        "lastTrained": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "derivation": "per_api_empirical_v1.1.0",
    }

    if model_json_path is None:
        repo_root = Path(__file__).resolve().parents[2]
        model_json_path = repo_root / "apiris" / "models" / "anomaly_model.json"
    else:
        model_json_path = Path(model_json_path)

    if model_json_path.exists():
        with open(model_json_path, "r", encoding="utf-8") as f:
            full_data = json.load(f)
    else:
        full_data = {"version": 1, "featureNames": [], "models": {}}

    full_data.setdefault("models", {})[api_name] = trained_model

    with open(model_json_path, "w", encoding="utf-8") as f:
        json.dump(full_data, f, indent=2)

    return {
        "api_name": api_name,
        "sample_count": n_samples,
        "core_fields_count": len(core_fields),
        "means": means,
        "stds": stds,
        "model_file": str(model_json_path),
    }

"""
Corpus Benchmark and Decision Engine Pipeline Evaluation Module for Apiris SDK
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from apiris.config import ApirisConfig, load_config
from apiris.decision_engine import DecisionEngine
from apiris.evaluator import ObservationEvaluator


def evaluate_single_sample(
    engine: DecisionEngine,
    evaluator: ObservationEvaluator,
    sample: Dict[str, Any],
) -> Tuple[Dict[str, Any], float]:
    url = sample["url"]
    api = sample["api"]
    status = sample.get("status", 200)
    headers = sample.get("headers", {})
    body = sample.get("body", "")
    latency_ms = sample.get("latency_ms", 50)

    parsed = None
    if body:
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = None

    t0 = time.perf_counter_ns()

    obs = evaluator.evaluate(
        api=api,
        request={"method": sample.get("method", "GET"), "url": url, "headers": {}},
        response={"status": status, "headers": headers, "body": body},
        error=None,
        runtime_context={"timing_ms": latency_ms},
    )

    decision_res = engine.evaluate(
        observation=obs,
        response_text=body,
        parsed=parsed,
        response_headers=headers,
        response_status=status,
    )

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    result = {
        "id": sample.get("id"),
        "api": api,
        "cad_scores": decision_res["decision"]["scores"],
        "action": decision_res["decision"]["action"],
        "tradeoff": decision_res["decision"]["tradeoff"],
        "confidence": decision_res["decision"]["confidence"],
        "pipeline_latency_ms": elapsed_ms,
    }
    return result, elapsed_ms


def calculate_percentiles(latencies: List[float]) -> Dict[str, float]:
    if not latencies:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
    sorted_lats = sorted(latencies)
    n = len(sorted_lats)

    def p(pct: float) -> float:
        k = (n - 1) * pct
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_lats[int(k)]
        return sorted_lats[f] * (c - k) + sorted_lats[c] * (k - f)

    return {
        "p50": round(p(0.50), 3),
        "p95": round(p(0.95), 3),
        "p99": round(p(0.99), 3),
        "mean": round(sum(sorted_lats) / n, 3),
    }


def run_corpus_benchmark(
    corpus_path: Optional[Path | str] = None,
    config: Optional[ApirisConfig] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> Dict[str, Any]:
    if corpus_path is None:
        repo_root = Path(__file__).resolve().parents[1]
        corpus_path = repo_root / "data" / "clean_traffic_corpus.json"
    else:
        corpus_path = Path(corpus_path)

    if not corpus_path.exists():
        raise FileNotFoundError(f"Corpus file not found: {corpus_path}")

    with open(corpus_path, "r", encoding="utf-8") as f:
        corpus_data = json.load(f)

    if config is None:
        config = ApirisConfig(
            strict_zero_tolerance=False,
            integrity_threshold=0.40,
            availability_threshold=0.40,
            anomaly_threshold=0.70,
            hysteresis_band=0.05,
            enable_ai=False,
        )

    clean_samples = corpus_data.get("clean_samples", [])
    degraded_samples = corpus_data.get("degraded_samples", [])
    adversarial_samples = corpus_data.get("adversarial_samples", [])

    total_samples = len(clean_samples) + len(degraded_samples) + len(adversarial_samples)
    current_idx = 0

    all_pipeline_latencies: List[float] = []

    # Category evaluations
    categories = [
        ("clean", clean_samples),
        ("degraded", degraded_samples),
        ("adversarial", adversarial_samples),
    ]

    category_results: Dict[str, Dict[str, Any]] = {}
    action_distribution: Dict[str, int] = {}

    for cat_name, samples in categories:
        engine = DecisionEngine(config)
        evaluator = ObservationEvaluator(config)
        results: List[Dict[str, Any]] = []
        cat_latencies: List[float] = []

        for sample in samples:
            res, lat = evaluate_single_sample(engine, evaluator, sample)
            results.append(res)
            cat_latencies.append(lat)
            all_pipeline_latencies.append(lat)
            act = res["action"]
            action_distribution[act] = action_distribution.get(act, 0) + 1

            current_idx += 1
            if progress_callback:
                progress_callback(current_idx, total_samples, f"Evaluating {cat_name}: {sample.get('id', '')}")

        cat_count = len(samples)
        pass_through_count = sum(1 for r in results if r["action"] == "pass_through")
        mean_conf = (sum(r["confidence"] for r in results) / cat_count) if cat_count else 0.0

        category_results[cat_name] = {
            "total": cat_count,
            "pass_through": pass_through_count,
            "pass_through_rate": (pass_through_count / cat_count) if cat_count else 0.0,
            "mean_confidence": round(mean_conf, 3),
            "latency": calculate_percentiles(cat_latencies),
            "samples": results,
        }

    clean_res = category_results.get("clean", {})
    clean_pass_rate = clean_res.get("pass_through_rate", 0.0)

    return {
        "corpus_version": corpus_data.get("version", "1.1.0"),
        "total_samples": total_samples,
        "clean_pass_through_rate": clean_pass_rate,
        "action_distribution": action_distribution,
        "pipeline_latency": calculate_percentiles(all_pipeline_latencies),
        "categories": category_results,
    }

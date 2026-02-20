from __future__ import annotations

import argparse
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from apiris import ApirisClient
from apiris.logging import append_jsonl


API_TARGETS = [
    (
        "CoinGecko",
        "https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids=bitcoin,ethereum",
    ),
    (
        "USGS Earthquake Feed",
        "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson",
    ),
    ("JSONPlaceholder", "https://jsonplaceholder.typicode.com/posts/1"),
    (
        "Open-Meteo",
        "https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&current_weather=true",
    ),
]


@dataclass
class CallResult:
    service_name: str
    status_code: Optional[int]
    latency_ms: int
    cad_scores: Dict[str, float]
    action: str
    tradeoff: str
    confidence: float
    overhead_ms: int
    error: Optional[str] = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _write_config(mode: str, enable_ai: bool, base_dir: Path) -> Path:
    config = {
        "Apiris": {
            "enable_ai": enable_ai,
            "integrity_threshold": 0.25,
            "availability_threshold": 0.40,
            "anomaly_threshold": 0.70,
            "mode": mode,
            "enable_explanation": False,
            "log_dir": str(base_dir / "runtime" / "logs"),
            "models_dir": str(base_dir / "models"),
            "window_ms": 300000,
            "cache_ttl_ms": 300000,
            "latency_budget_ms": 1000,
        }
    }
    config_path = base_dir / "runtime" / f"config_{mode}_{'ai' if enable_ai else 'noai'}.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config))
    return config_path


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])


def _fetch_raw(session: requests.Session, url: str, timeout: float = 10.0) -> Tuple[Optional[dict], Optional[str], int, Optional[str]]:
    started = time.time()
    try:
        response = session.get(url, timeout=timeout)
        latency_ms = int((time.time() - started) * 1000)
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
        }, None, latency_ms, None
    except requests.RequestException as exc:
        latency_ms = int((time.time() - started) * 1000)
        return None, str(exc), latency_ms, "request_error"


def _apply_stress(response: dict, stress_integrity: bool, stress_availability: bool) -> dict:
    modified = dict(response)
    body_text = modified.get("body")
    if not isinstance(body_text, str):
        return modified

    parsed = None
    try:
        parsed = json.loads(body_text)
    except json.JSONDecodeError:
        parsed = None

    if stress_integrity and parsed is not None:
        random.seed(42)
        if isinstance(parsed, dict) and parsed:
            key = random.choice(list(parsed.keys()))
            parsed.pop(key, None)
            body_text = json.dumps(parsed)
        elif isinstance(parsed, list) and parsed:
            parsed = parsed[1:]
            body_text = json.dumps(parsed)

    if stress_availability and body_text:
        cutoff = max(1, len(body_text) // 2)
        body_text = body_text[:cutoff]

    modified["body"] = body_text
    return modified


def _evaluate_with_client(
    client: ApirisClient,
    url: str,
    stress_latency: bool,
    stress_integrity: bool,
    stress_availability: bool,
) -> CallResult:
    parsed_url = urlparse(url)
    api_name = parsed_url.netloc or url
    endpoint = parsed_url.path or "/"

    total_start = time.time()
    response, error, latency_ms, error_type = _fetch_raw(client.session, url)
    if error:
        return CallResult(
            service_name=api_name,
            status_code=None,
            latency_ms=latency_ms,
            cad_scores={},
            action="error",
            tradeoff="none",
            confidence=0.0,
            overhead_ms=0,
            error=error,
        )

    response = _apply_stress(response or {}, stress_integrity, stress_availability)
    if stress_latency:
        time.sleep(0.3)

    request_payload = {
        "method": "GET",
        "url": url,
        "headers": {},
        "params": {},
    }

    observation = client.evaluator.evaluate(
        api=api_name,
        request=request_payload,
        response=response or {},
        error=None,
        runtime_context={
            "run_id": "Apiris",
            "seq": 0,
            "interval_ms": 0,
            "duration_ms": 0,
            "soft_timeout_ms": 0,
            "timing_ms": latency_ms,
            "vs_currency": "usd",
            "request_id": None,
        },
    )

    response_text = response.get("body") if response else None
    parsed_body = None
    if response_text:
        try:
            parsed_body = json.loads(response_text)
        except json.JSONDecodeError:
            parsed_body = None

    decision_result = client.decision_engine.evaluate(
        observation=observation,
        response_text=response_text,
        parsed=parsed_body,
        response_headers=response.get("headers") if response else None,
        response_status=response.get("status") if response else None,
    )
    decision = decision_result["decision"]

    client.interceptor.apply(
        action=decision.get("action", "pass_through"),
        response_text=response_text,
        parsed=parsed_body,
        response_headers=response.get("headers") if response else None,
        response_status=response.get("status") if response else None,
        cache=client.decision_engine.get_cache(api_name),
        cache_ttl_ms=client.config.cache_ttl_ms,
    )

    cad_scores = decision.get("scores", {})
    if client.ai_enabled:
        ai_signals = {
            "enabled": True,
            "anomaly_score": observation.get("integrity", {}).get("aiAnomalyScore"),
            "anomaly_flag": observation.get("integrity", {}).get("aiAnomalyFlag"),
            "anomaly_features": observation.get("integrity", {}).get("aiTopFeatures"),
            "anomaly_schema_hash": observation.get("integrity", {}).get("aiSchemaHash"),
        }
    else:
        ai_signals = {"enabled": False}

    decision_payload = {
        "action": decision.get("action", "pass_through"),
        "tradeoff": decision.get("tradeoff", "none"),
        "confidence": float(decision.get("confidence", 0.0)),
    }

    log_entry = {
        "event_id": observation.get("id"),
        "timestamp": observation.get("ts"),
        "api": api_name,
        "service_name": api_name,
        "endpoint": endpoint,
        "cad_scores": cad_scores,
        "ai_signals": ai_signals,
        "decision": decision_payload,
        "mode": client.config.mode,
        "latency_ms": observation.get("availability", {}).get("latencyMs"),
        "schema_changed": observation.get("integrity", {}).get("schemaChanged"),
    }

    append_jsonl(client.log_paths["observations"], log_entry)
    append_jsonl(client.log_paths["decisions"], log_entry)
    if client.ai_enabled:
        append_jsonl(client.log_paths["predictions"], log_entry)
        append_jsonl(client.log_paths["anomalies"], log_entry)

    total_ms = int((time.time() - total_start) * 1000)
    overhead_ms = max(0, total_ms - latency_ms)

    return CallResult(
        service_name=api_name,
        status_code=response.get("status") if response else None,
        latency_ms=latency_ms,
        cad_scores=cad_scores,
        action=decision_payload["action"],
        tradeoff=decision_payload["tradeoff"],
        confidence=decision_payload["confidence"],
        overhead_ms=overhead_ms,
        error=None,
    )


def _print_result(label: str, result: CallResult) -> None:
    print(f"=== Testing: {label} ===")
    if result.error:
        print(f"Error: {result.error}")
        return
    print(f"Status: {result.status_code}")
    print(f"Latency: {result.latency_ms} ms")
    print(f"CAD: {result.cad_scores}")
    print(f"Action: {result.action}")
    print(f"Tradeoff: {result.tradeoff}")
    print(f"Confidence: {result.confidence}")
    print(f"Overhead: {result.overhead_ms} ms")


def main() -> int:
    parser = argparse.ArgumentParser(description="Apiris real API validation")
    parser.add_argument("--stress-latency", action="store_true")
    parser.add_argument("--stress-integrity", action="store_true")
    parser.add_argument("--stress-availability", action="store_true")
    args = parser.parse_args()

    repo_root = _repo_root()
    log_dir = repo_root / "runtime" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    observation_log = log_dir / "cad_observations.jsonl"
    decision_log = log_dir / "cad_decisions.jsonl"
    baseline_counts = {
        "observations": _count_lines(observation_log),
        "decisions": _count_lines(decision_log),
    }

    mode_matrix = [
        ("enforce", False),
        ("enforce", True),
        ("strict", False),
        ("strict", True),
    ]

    total_calls = 0
    failures = 0
    integrity_violations = 0
    availability_issues = 0
    confidence_values: List[float] = []

    for mode, enable_ai in mode_matrix:
        print(f"\n=== Mode: {mode} | AI: {enable_ai} ===")
        config_path = _write_config(mode, enable_ai, repo_root)
        client = ApirisClient(config_path=str(config_path))

        baselines: Dict[str, int] = {}
        for label, url in API_TARGETS:
            response, error, latency_ms, _ = _fetch_raw(client.session, url)
            if error:
                print(f"=== Baseline: {label} ===")
                print(f"Error: {error}")
                failures += 1
            else:
                baselines[url] = latency_ms
                print(f"=== Baseline: {label} ===")
                print(f"Latency: {latency_ms} ms")
            time.sleep(2)

        for label, url in API_TARGETS:
            result = _evaluate_with_client(
                client,
                url,
                stress_latency=args.stress_latency,
                stress_integrity=args.stress_integrity,
                stress_availability=args.stress_availability,
            )
            _print_result(label, result)
            total_calls += 1
            if result.error:
                failures += 1
            else:
                confidence_values.append(result.confidence)
                if result.action == "reject_response":
                    integrity_violations += 1
                if result.action in {"serve_stale_cache", "delay_response", "downgrade_fidelity"}:
                    availability_issues += 1

                baseline_latency = baselines.get(url)
                if baseline_latency is not None:
                    overhead = max(0, result.latency_ms - baseline_latency)
                    print(f"Baseline latency: {baseline_latency} ms")
                    print(f"Apiris latency: {result.latency_ms} ms")
                    print(f"Overhead: {overhead} ms")
            time.sleep(2)

    new_counts = {
        "observations": _count_lines(observation_log),
        "decisions": _count_lines(decision_log),
    }
    added_observations = new_counts["observations"] - baseline_counts["observations"]
    added_decisions = new_counts["decisions"] - baseline_counts["decisions"]

    print("\n=== Logging Verification ===")
    print(f"cad_observations.jsonl new entries: {added_observations}")
    print(f"cad_decisions.jsonl new entries: {added_decisions}")

    avg_confidence = sum(confidence_values) / max(len(confidence_values), 1)

    print("\n=== Summary ===")
    print(f"Total APIs Tested: {total_calls}")
    print(f"Total Failures: {failures}")
    print(f"Total Integrity Violations: {integrity_violations}")
    print(f"Total Availability Issues: {availability_issues}")
    print(f"Average Decision Confidence: {avg_confidence:.2f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


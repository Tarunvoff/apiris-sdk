from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from .config import ApirisConfig
from .ai.anomaly_model import AnomalyScorer


def _hash_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _safe_json_parse(text: Optional[str]) -> Optional[Any]:
    if not text or not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _extract_schema_paths(value: Any, prefix: str = "", depth: int = 0, max_depth: int = 3, paths: Optional[set] = None) -> set:
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


def _scan_keys_for_matches(value: Any, patterns: list, matches: set, path_prefix: str = "") -> None:
    if not isinstance(value, (dict, list)):
        return
    if isinstance(value, list):
        for item in value:
            _scan_keys_for_matches(item, patterns, matches, path_prefix)
        return
    for key, val in value.items():
        next_path = f"{path_prefix}.{key}" if path_prefix else str(key)
        lower = str(key).lower()
        for pattern in patterns:
            if pattern in lower:
                matches.add(next_path)
        _scan_keys_for_matches(val, patterns, matches, next_path)


def _detect_sensitive_fields(parsed: Any, raw_text: Optional[str]) -> list:
    patterns = ["password", "secret", "token", "api_key", "api-key", "auth", "cookie", "session", "jwt"]
    matches: set = set()
    _scan_keys_for_matches(parsed, patterns, matches)
    if raw_text:
        lower = raw_text.lower()
        for pattern in patterns:
            if pattern in lower:
                matches.add(f"raw:{pattern}")
    return sorted(matches)


def _detect_auth_hints(parsed: Any, raw_text: Optional[str]) -> list:
    patterns = ["auth", "token", "bearer", "key", "session"]
    matches: set = set()
    _scan_keys_for_matches(parsed, patterns, matches)
    if raw_text:
        lower = raw_text.lower()
        for pattern in patterns:
            if pattern in lower:
                matches.add(f"raw:{pattern}")
    return sorted(matches)


def _detect_verbose_errors(status: Optional[int], body_text: Optional[str]) -> list:
    if not body_text or not status or status < 400:
        return []
    patterns = ["exception", "stacktrace", "traceback", "nullreference", "typeerror", "referenceerror", " at "]
    signals = []
    lower = body_text.lower()
    for pattern in patterns:
        if pattern in lower:
            signals.append(pattern)
    return signals


def _detect_header_exposure(headers: Optional[Dict[str, str]]) -> list:
    if not headers:
        return []
    sensitive = {"set-cookie", "authorization", "www-authenticate", "x-api-key", "x-auth-token"}
    return [key for key in headers if key.lower() in sensitive]


def _get_cache_indicators(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    if not headers:
        return None
    indicators = {}
    cache_keys = ["cache-control", "age", "expires", "etag", "last-modified", "cf-cache-status", "x-cache"]
    for key in cache_keys:
        if key in headers:
            indicators[key] = headers[key]
    return indicators or None


def _is_timeout_error(error: Optional[Dict[str, str]]) -> bool:
    if not error:
        return False
    text = f"{error.get('name', '')} {error.get('message', '')}".lower()
    return "timeout" in text or "timedout" in text or "etimedout" in text


def _extract_coingecko_prices(api_name: str, parsed: Any, vs_currency: str) -> Optional[Dict[str, float]]:
    if not parsed:
        return None
    if api_name == "coingecko-simple-price" and isinstance(parsed, dict):
        return {
            key: float(entry.get(vs_currency))
            for key, entry in parsed.items()
            if isinstance(entry, dict) and entry.get(vs_currency) is not None
        }
    if api_name == "coingecko-markets" and isinstance(parsed, list):
        return {
            entry.get("id"): float(entry.get("current_price"))
            for entry in parsed
            if isinstance(entry, dict) and entry.get("id") is not None and entry.get("current_price") is not None
        }
    return None


class ObservationEvaluator:
    def __init__(self, config: ApirisConfig, anomaly_scorer: Optional[AnomalyScorer] = None) -> None:
        self.config = config
        self.anomaly_scorer = anomaly_scorer
        self.schema_by_api: Dict[str, str] = {}
        self.last_response_by_signature: Dict[str, Dict[str, Any]] = {}
        self.latest_prices: Dict[str, Dict[str, float]] = {"simple": {}, "markets": {}}
        self.anomaly_runtime: Dict[str, Dict[str, Any]] = {}

    def _build_cross_endpoint_inconsistencies(self, api_name: str, parsed: Any, vs_currency: str) -> Optional[list]:
        price_map = _extract_coingecko_prices(api_name, parsed, vs_currency)
        if not price_map:
            return None
        store_key = "simple" if api_name == "coingecko-simple-price" else "markets"
        other_key = "markets" if store_key == "simple" else "simple"
        self.latest_prices[store_key] = price_map
        other_map = self.latest_prices.get(other_key) or {}
        if not other_map:
            return None

        inconsistencies = []
        for key, value in price_map.items():
            if key in other_map:
                other_value = other_map[key]
                delta = value - other_value
                if delta != 0:
                    inconsistencies.append({"id": key, "current": value, "other": other_value, "delta": delta})
        return inconsistencies or None

    def evaluate(self, api: str, request: Dict[str, Any], response: Dict[str, Any], error: Optional[Dict[str, str]], runtime_context: Dict[str, Any]) -> Dict[str, Any]:
        request_id = uuid.uuid4().hex
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        response_text = response.get("body") if response else None
        response_headers = response.get("headers") if response else None
        response_status = response.get("status") if response else None
        parsed = _safe_json_parse(response_text)

        schema_paths = _extract_schema_paths(parsed) if parsed is not None else set()
        schema_hash = _hash_text("|".join(sorted(schema_paths))) if schema_paths else None
        previous_schema_hash = self.schema_by_api.get(api)
        schema_changed = bool(schema_hash and previous_schema_hash and schema_hash != previous_schema_hash)
        if schema_hash:
            self.schema_by_api[api] = schema_hash

        signature = f"{request.get('method', 'GET')} {request.get('url', '')}"
        previous_response = self.last_response_by_signature.get(signature)
        response_hash = _hash_text(response_text) if response_text else None
        drift_detected = bool(response_hash and previous_response and response_hash != previous_response.get("hash"))
        replayed_payload = bool(response_hash and previous_response and response_hash == previous_response.get("hash"))

        now_ms = int(time.time() * 1000)
        self.last_response_by_signature[signature] = {
            "hash": response_hash,
            "ts": now_ms,
            "count": (previous_response.get("count", 0) + 1) if previous_response else 1,
        }

        cache_indicators = _get_cache_indicators(response_headers)
        rate_limited = bool(response_status == 429) or bool(
            response_headers
            and (response_headers.get("x-ratelimit-remaining") == "0" or response_headers.get("x-rate-limit-remaining") == "0")
        )
        timeout_error = _is_timeout_error(error)
        soft_timeout_exceeded = runtime_context.get("soft_timeout_ms", 0) > 0 and runtime_context.get("timing_ms", 0) >= runtime_context.get("soft_timeout_ms", 0)

        confidentiality = {
            "sensitiveFields": _detect_sensitive_fields(parsed, response_text),
            "authHintsInPayload": _detect_auth_hints(parsed, response_text),
            "verboseErrorSignals": _detect_verbose_errors(response_status, response_text),
            "headerExposure": _detect_header_exposure(response_headers or {}),
        }

        integrity = {
            "schemaHash": schema_hash,
            "previousSchemaHash": previous_schema_hash,
            "schemaChanged": schema_changed,
            "responseHash": response_hash,
            "temporalDrift": {
                "previousHash": previous_response.get("hash") if drift_detected and previous_response else None,
                "sinceMs": now_ms - previous_response.get("ts") if drift_detected and previous_response else None,
            } if drift_detected else None,
            "replayedPayload": {
                "hash": response_hash,
                "repeatCount": previous_response.get("count") if replayed_payload and previous_response else 1,
                "sinceMs": now_ms - previous_response.get("ts") if replayed_payload and previous_response else None,
            } if replayed_payload else None,
            "crossEndpointInconsistencies": self._build_cross_endpoint_inconsistencies(api, parsed, runtime_context.get("vs_currency", "usd")),
        }

        if self.config.enable_ai and self.anomaly_scorer:
            try:
                anomaly_result = self.anomaly_scorer.score(api, parsed, response_text, self.anomaly_runtime, now_ms)
            except Exception:
                anomaly_result = None
            if anomaly_result:
                integrity.update({
                    "aiAnomalyScore": anomaly_result["anomalyScore"],
                    "aiAnomalyFlag": anomaly_result["anomalyFlag"],
                    "aiTopFeatures": anomaly_result["topFeatures"],
                    "aiSchemaHash": anomaly_result["schemaHash"],
                })

        observation = {
            "id": request_id,
            "runId": runtime_context.get("run_id"),
            "seq": runtime_context.get("seq"),
            "ts": now_iso,
            "api": api,
            "mode": self.config.mode,
            "request": {
                "method": request.get("method"),
                "url": request.get("url"),
                "headers": request.get("headers", {}),
                "body": request.get("body"),
                "signature": signature,
            },
            "response": {
                "status": response_status,
                "headers": response_headers,
                "bodyBytes": len(response_text.encode("utf-8")) if response_text else 0,
                "contentType": (response_headers or {}).get("content-type"),
            } if response else None,
            "confidentiality": confidentiality,
            "availability": {
                "latencyMs": runtime_context.get("timing_ms"),
                "softTimeoutExceeded": soft_timeout_exceeded or None,
                "timeoutError": timeout_error,
                "rateLimited": rate_limited,
                "status": response_status,
                "cacheIndicators": cache_indicators,
                "error": error,
            },
            "integrity": integrity,
            "context": {
                "intervalMs": runtime_context.get("interval_ms"),
                "durationMs": runtime_context.get("duration_ms"),
            },
        }

        return observation

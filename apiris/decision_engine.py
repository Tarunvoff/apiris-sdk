from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .cache import ResponseCache
from .config import ApirisConfig
from .policy.policy_manager import PolicyManager


DEFAULT_PROFILE = {
    "confidentiality_threshold": None,
    "availability_threshold": None,
    "integrity_threshold": None,
    "availability_delay_threshold": None,
    "confidentiality_weight": 1.0,
    "availability_weight": 1.0,
    "integrity_weight": 1.0,
    "latency_budget_ms": 1000,
    "prefer": "availability",
    "delay_ms": 400,
}


def _hash_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _mask_sensitive_fields(value: Any, depth: int = 0, max_depth: int = 6) -> Any:
    if depth > max_depth:
        return value
    if isinstance(value, list):
        return [_mask_sensitive_fields(item, depth + 1, max_depth) for item in value]
    if not isinstance(value, dict):
        return value

    patterns = [
        "password",
        "secret",
        "token",
        "api_key",
        "api-key",
        "auth",
        "cookie",
        "session",
        "jwt",
    ]
    result: Dict[str, Any] = {}
    for key, val in value.items():
        key_lower = str(key).lower()
        if any(pattern in key_lower for pattern in patterns):
            result[key] = "[MASKED]"
        else:
            result[key] = _mask_sensitive_fields(val, depth + 1, max_depth)
    return result


@dataclass
class DecisionEngineState:
    window: list = field(default_factory=list)
    cache: Optional[ResponseCache] = None


class DecisionEngine:
    def __init__(self, config: ApirisConfig, profiles: Optional[Dict[str, Dict[str, Any]]] = None, policy_manager: Optional[PolicyManager] = None) -> None:
        self.config = config
        self.window_ms = config.window_ms
        self.cache_ttl_ms = config.cache_ttl_ms
        self.ai_anomaly_weight = 0.0
        self.profiles = profiles or {}
        self.policy_manager = policy_manager
        self.state: Dict[str, DecisionEngineState] = {}

    def _get_profile(self, api: str, endpoint: Optional[str] = None) -> Dict[str, Any]:
        profile = DEFAULT_PROFILE.copy()
        profile.update(
            {
                "confidentiality_threshold": self.config.confidentiality_threshold,
                "availability_threshold": self.config.availability_threshold,
                "integrity_threshold": self.config.integrity_threshold,
                "availability_delay_threshold": self.config.availability_threshold,
                "latency_budget_ms": self.config.latency_budget_ms,
            }
        )
        profile.update(self.profiles.get(api, {}))
        if self.policy_manager:
            profile = self.policy_manager.apply_to_profile(profile, api, endpoint)
        if self.config.mode == "strict":
            profile["integrity_threshold"] = self.config.integrity_threshold
            profile["prefer"] = "integrity"
        return profile

    def _get_state(self, api: str) -> DecisionEngineState:
        if api not in self.state:
            self.state[api] = DecisionEngineState()
        return self.state[api]

    def _summarize_signals(self, observation: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        confidentiality = observation.get("confidentiality") or {}
        availability = observation.get("availability") or {}
        integrity = observation.get("integrity") or {}

        confidentiality_signals = (
            len(confidentiality.get("sensitiveFields") or [])
            + len(confidentiality.get("authHintsInPayload") or [])
            + len(confidentiality.get("verboseErrorSignals") or [])
            + len(confidentiality.get("headerExposure") or [])
        )

        availability_signals = (
            int(bool(availability.get("rateLimited")))
            + int(bool(availability.get("timeoutError")))
            + int(bool(availability.get("softTimeoutExceeded")))
            + int(bool(availability.get("status") and availability.get("status") >= 500))
            + int(bool(availability.get("latencyMs", 0) > profile["latency_budget_ms"]))
        )

        integrity_signals = (
            int(bool(integrity.get("schemaChanged")))
            + int(bool(integrity.get("temporalDrift")))
            + int(bool(integrity.get("replayedPayload")))
            + int(bool(integrity.get("crossEndpointInconsistencies")))
        )

        ai_anomaly_score = integrity.get("aiAnomalyScore")
        if not isinstance(ai_anomaly_score, (int, float)):
            ai_anomaly_score = 0

        return {
            "confidentialitySignals": confidentiality_signals,
            "availabilitySignals": availability_signals,
            "integritySignals": integrity_signals,
            "aiAnomalyScore": ai_anomaly_score,
        }
    
    def _extract_scoring_factors(self, observation: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all features/factors considered in CIA scoring for transparency.
        Returns structured list of factors used in computation.
        """
        confidentiality = observation.get("confidentiality") or {}
        availability = observation.get("availability") or {}
        integrity = observation.get("integrity") or {}
        
        factors = {
            "confidentiality_factors": [],
            "availability_factors": [],
            "integrity_factors": [],
            "thresholds": {
                "confidentiality_threshold": profile["confidentiality_threshold"],
                "availability_threshold": profile["availability_threshold"],
                "integrity_threshold": profile["integrity_threshold"],
                "latency_budget_ms": profile["latency_budget_ms"],
            }
        }
        
        # Confidentiality factors
        sensitive_fields = confidentiality.get("sensitiveFields") or []
        if sensitive_fields:
            factors["confidentiality_factors"].append({
                "name": "Sensitive Fields Detected",
                "count": len(sensitive_fields),
                "impact": "negative",
                "details": sensitive_fields[:3]  # First 3 for brevity
            })
        
        auth_hints = confidentiality.get("authHintsInPayload") or []
        if auth_hints:
            factors["confidentiality_factors"].append({
                "name": "Auth Hints in Payload",
                "count": len(auth_hints),
                "impact": "negative",
                "details": auth_hints[:3]
            })
        
        verbose_errors = confidentiality.get("verboseErrorSignals") or []
        if verbose_errors:
            factors["confidentiality_factors"].append({
                "name": "Verbose Error Signals",
                "count": len(verbose_errors),
                "impact": "negative",
                "details": verbose_errors[:3]
            })
        
        header_exposure = confidentiality.get("headerExposure") or []
        if header_exposure:
            factors["confidentiality_factors"].append({
                "name": "Exposed Headers",
                "count": len(header_exposure),
                "impact": "negative",
                "details": header_exposure[:3]
            })
        
        # Availability factors
        latency_ms = availability.get("latencyMs", 0)
        if latency_ms:
            factors["availability_factors"].append({
                "name": "Response Latency",
                "value": f"{latency_ms}ms",
                "impact": "negative" if latency_ms > profile["latency_budget_ms"] else "neutral",
                "budget": f"{profile['latency_budget_ms']}ms"
            })
        
        if availability.get("rateLimited"):
            factors["availability_factors"].append({
                "name": "Rate Limited",
                "value": True,
                "impact": "negative"
            })
        
        if availability.get("timeoutError"):
            factors["availability_factors"].append({
                "name": "Timeout Error",
                "value": True,
                "impact": "negative"
            })
        
        if availability.get("softTimeoutExceeded"):
            factors["availability_factors"].append({
                "name": "Soft Timeout Exceeded",
                "value": True,
                "impact": "negative"
            })
        
        status = availability.get("status")
        if status and status >= 500:
            factors["availability_factors"].append({
                "name": "Server Error",
                "value": f"HTTP {status}",
                "impact": "negative"
            })
        
        # Integrity factors
        if integrity.get("schemaChanged"):
            factors["integrity_factors"].append({
                "name": "Schema Changed",
                "value": True,
                "impact": "negative",
                "previous_hash": integrity.get("previousSchemaHash", "")[:8]
            })
        
        if integrity.get("temporalDrift"):
            drift = integrity["temporalDrift"]
            factors["integrity_factors"].append({
                "name": "Temporal Drift Detected",
                "value": True,
                "impact": "negative",
                "since_ms": drift.get("sinceMs")
            })
        
        if integrity.get("replayedPayload"):
            replay = integrity["replayedPayload"]
            factors["integrity_factors"].append({
                "name": "Replayed Payload",
                "value": True,
                "impact": "neutral",
                "repeat_count": replay.get("repeatCount")
            })
        
        cross_inconsistencies = integrity.get("crossEndpointInconsistencies")
        if cross_inconsistencies:
            factors["integrity_factors"].append({
                "name": "Cross-Endpoint Inconsistencies",
                "count": len(cross_inconsistencies),
                "impact": "negative"
            })
        
        ai_score = integrity.get("aiAnomalyScore")
        if ai_score and ai_score > 0:
            factors["integrity_factors"].append({
                "name": "AI Anomaly Score",
                "value": round(ai_score, 3),
                "impact": "negative" if ai_score > 0.5 else "neutral",
                "top_features": integrity.get("aiTopFeatures", [])[:3]
            })
        
        return factors

    def _compute_score(self, signal_rate: float, weight: float) -> float:
        return max(0.0, 1.0 - signal_rate * weight)

    def _compute_scores(self, aggregates: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        total = aggregates.get("total", 1) or 1
        confidentiality_rate = aggregates["confidentialitySignals"] / total
        availability_rate = aggregates["availabilitySignals"] / total
        integrity_rate = aggregates["integritySignals"] / total

        return {
            "C_score": self._compute_score(confidentiality_rate, profile["confidentiality_weight"]),
            "A_score": self._compute_score(availability_rate, profile["availability_weight"]),
            "D_score": self._compute_score(integrity_rate, profile["integrity_weight"]),
            "integrityRate": integrity_rate,
        }

    def _enforce_integrity_priority(self, scores: Dict[str, Any], profile: Dict[str, Any]) -> Optional[Dict[str, str]]:
        d_score = scores["D_score"]
        if d_score < profile["integrity_threshold"]:
            return {
                "action": "reject_response",
                "tradeoff": "integrity_over_availability",
                "justification": f"Strict mode: D_score {d_score:.2f} below {profile['integrity_threshold']}",
            }
        return None

    def _choose_action(self, scores: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, str]:
        c_score = scores["C_score"]
        a_score = scores["A_score"]
        d_score = scores["D_score"]
        if self.config.mode == "strict":
            strict_action = self._enforce_integrity_priority(scores, profile)
            if strict_action:
                return strict_action

        if c_score < profile["confidentiality_threshold"]:
            return {
                "action": "mask_sensitive_fields",
                "tradeoff": "confidentiality_over_completeness",
                "justification": f"C_score {c_score:.2f} below {profile['confidentiality_threshold']}",
            }

        if a_score < profile["availability_threshold"] and d_score >= profile["integrity_threshold"]:
            return {
                "action": "serve_stale_cache",
                "tradeoff": "availability_over_integrity",
                "justification": f"A_score {a_score:.2f} below {profile['availability_threshold']} while D_score {d_score:.2f} >= {profile['integrity_threshold']}",
            }

        if d_score < profile["integrity_threshold"] and a_score >= profile["availability_threshold"]:
            return {
                "action": "reject_response",
                "tradeoff": "integrity_over_availability",
                "justification": f"D_score {d_score:.2f} below {profile['integrity_threshold']} while A_score {a_score:.2f} >= {profile['availability_threshold']}",
            }

        if a_score < profile["availability_threshold"] and d_score < profile["integrity_threshold"]:
            action = "serve_stale_cache" if profile["prefer"] == "availability" else "downgrade_fidelity"
            tradeoff = "availability_over_integrity" if profile["prefer"] == "availability" else "integrity_over_availability"
            return {
                "action": action,
                "tradeoff": tradeoff,
                "justification": f"Both A_score {a_score:.2f} and D_score {d_score:.2f} below thresholds; prefer {profile['prefer']}",
            }

        if a_score < profile["availability_delay_threshold"]:
            return {
                "action": "delay_response",
                "tradeoff": "integrity_over_availability",
                "justification": f"A_score {a_score:.2f} below {profile['availability_delay_threshold']}, apply delay",
            }

        return {
            "action": "pass_through",
            "tradeoff": "none",
            "justification": "Scores within acceptable bounds",
        }

    def _compute_confidence(self, scores: Dict[str, Any], scores_with_ai: Dict[str, Any], profile: Dict[str, Any], action: str, ai_used: bool) -> float:
        def clamp(value: float) -> float:
            return max(0.0, min(1.0, value))

        def breach(score: float, threshold: Optional[float]) -> float:
            if threshold is None or threshold <= 0:
                return 0.0
            if score >= threshold:
                return 0.0
            return clamp((threshold - score) / max(threshold, 1e-6))

        thresholds = {
            "C_score": profile["confidentiality_threshold"],
            "A_score": profile["availability_threshold"],
            "D_score": profile["integrity_threshold"],
        }
        in_bounds = all(
            scores[key] >= (thresholds[key] if thresholds[key] is not None else 0.0)
            for key in ("C_score", "A_score", "D_score")
        )

        if action == "pass_through" and in_bounds:
            base_confidence = 1.0
        elif self.config.mode == "passive":
            base_confidence = 1.0
        elif self.config.mode == "strict" and scores["D_score"] < profile["integrity_threshold"]:
            base_confidence = 1.0
        else:
            base_confidence = max(
                breach(scores["C_score"], profile["confidentiality_threshold"]),
                breach(scores["A_score"], profile["availability_threshold"]),
                breach(scores["D_score"], profile["integrity_threshold"]),
            )

        if ai_used:
            ai_confidence = clamp(float(scores_with_ai.get("aiAnomalyAvg", 0.0)))
            base_confidence = max(base_confidence, ai_confidence)

        return round(clamp(base_confidence), 2)

    def get_cache(self, api: str) -> Optional[ResponseCache]:
        return self._get_state(api).cache

    def _aggregate_window(self, window: list) -> Dict[str, Any]:
        aggregates = {
            "total": len(window),
            "confidentialitySignals": 0,
            "availabilitySignals": 0,
            "integritySignals": 0,
            "aiAnomalyScoreSum": 0.0,
            "aiAnomalyScoreCount": 0,
        }
        for entry in window:
            aggregates["confidentialitySignals"] += entry["confidentialitySignals"]
            aggregates["availabilitySignals"] += entry["availabilitySignals"]
            aggregates["integritySignals"] += entry["integritySignals"]
            if entry["aiAnomalyScore"] > 0:
                aggregates["aiAnomalyScoreSum"] += entry["aiAnomalyScore"]
                aggregates["aiAnomalyScoreCount"] += 1
        return aggregates

    def _build_effective_response(self, action: str, input_data: Dict[str, Any], cache: Optional[ResponseCache], profile: Dict[str, Any]) -> Dict[str, Any]:
        response_text = input_data.get("response_text")
        parsed = input_data.get("parsed")
        response_headers = input_data.get("response_headers") or {}
        response_status = input_data.get("response_status")

        if action == "pass_through" or response_status is None:
            return {"applied": False, "effectiveResponse": None}

        if action == "mask_sensitive_fields":
            if not isinstance(parsed, dict):
                return {"applied": False, "effectiveResponse": None, "reason": "non-json-response"}
            masked = _mask_sensitive_fields(parsed)
            return {
                "applied": True,
                "effectiveResponse": {
                    "status": response_status,
                    "headers": response_headers,
                    "body": json.dumps(masked),
                    "contentType": "application/json",
                    "modified": "masked_sensitive_fields",
                },
            }

        if action == "serve_stale_cache":
            if not cache or (time.time() * 1000 - cache.ts) > self.cache_ttl_ms:
                return {"applied": False, "effectiveResponse": None, "reason": "cache_unavailable"}
            return {
                "applied": True,
                "effectiveResponse": {
                    "status": cache.status,
                    "headers": cache.headers,
                    "body": cache.body,
                    "contentType": cache.content_type,
                    "modified": "served_stale_cache",
                    "cacheAgeMs": time.time() * 1000 - cache.ts,
                },
            }

        if action == "reject_response":
            return {
                "applied": True,
                "effectiveResponse": {
                    "blocked": True,
                    "reason": "integrity_risk",
                    "status": 503,
                },
            }

        if action == "downgrade_fidelity":
            return {
                "applied": True,
                "effectiveResponse": {
                    "status": response_status,
                    "headers": response_headers,
                    "body": None,
                    "bodyHash": _hash_text(response_text or ""),
                    "bodyBytes": len(response_text.encode("utf-8")) if response_text else 0,
                    "modified": "metadata_only",
                },
            }

        if action == "delay_response":
            return {
                "applied": True,
                "effectiveResponse": {
                    "status": response_status,
                    "headers": response_headers,
                    "body": response_text,
                    "contentType": response_headers.get("content-type"),
                    "modified": "delayed",
                    "delayMs": profile["delay_ms"],
                },
            }

        return {"applied": False, "effectiveResponse": None}

    def _update_cache(self, api_state: DecisionEngineState, response_text: Optional[str], response_headers: Optional[Dict[str, str]], response_status: Optional[int], scores: Dict[str, Any]) -> None:
        if not response_text or not response_headers or not response_status:
            return
        if scores["D_score"] < self.config.integrity_threshold:
            return
        api_state.cache = ResponseCache(
            ts=time.time() * 1000,
            status=response_status,
            headers=response_headers,
            body=response_text,
            content_type=response_headers.get("content-type"),
        )

    def evaluate(self, observation: Dict[str, Any], response_text: Optional[str], parsed: Any, response_headers: Optional[Dict[str, str]], response_status: Optional[int]) -> Dict[str, Any]:
        # Phase 1 determinism guarantee:
        # Intelligence modules may advise but never override hard rules.
        api = observation.get("api", "unknown")
        request_url = (observation.get("request") or {}).get("url")
        endpoint = urlparse(request_url).path if request_url else None
        profile = self._get_profile(api, endpoint)
        api_state = self._get_state(api)

        signal_summary = self._summarize_signals(observation, profile)
        entry = {"ts": int(time.time() * 1000), **signal_summary}
        api_state.window.append(entry)
        api_state.window = [item for item in api_state.window if item["ts"] >= entry["ts"] - self.window_ms]

        aggregates = self._aggregate_window(api_state.window)
        scores = self._compute_scores(aggregates, profile)
        if self.config.mode == "strict":
            profile = {**profile, "prefer": "integrity"}
        decision_choice = self._choose_action(scores, profile)
        if self.config.mode == "passive":
            decision_choice = {
                "action": "pass_through",
                "tradeoff": "none",
                "justification": "Passive mode: observe only",
            }

        ai_avg = (
            aggregates["aiAnomalyScoreSum"] / aggregates["aiAnomalyScoreCount"]
            if aggregates["aiAnomalyScoreCount"]
            else 0
        )
        scores_with_ai = {
            **scores,
            "D_score_ai": self._compute_score(scores["integrityRate"] + self.ai_anomaly_weight * ai_avg, profile["integrity_weight"]),
            "aiAnomalyAvg": ai_avg,
        }
        ai_used = aggregates["aiAnomalyScoreCount"] > 0

        self._update_cache(api_state, response_text, response_headers, response_status, scores)

        applied = self._build_effective_response(
            decision_choice["action"],
            {
                "response_text": response_text,
                "parsed": parsed,
                "response_headers": response_headers,
                "response_status": response_status,
            },
            api_state.cache,
            profile,
        )

        decision = {
            "id": observation.get("id"),
            "runId": observation.get("runId"),
            "seq": observation.get("seq"),
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "api": api,
            "scores": scores,
            "scoresWithAi": scores_with_ai,
            "aggregates": aggregates,
            "action": decision_choice["action"],
            "tradeoff": decision_choice["tradeoff"],
            "justification": decision_choice["justification"],
            "confidence": self._compute_confidence(scores, scores_with_ai, profile, decision_choice["action"], ai_used),
            "applied": applied.get("applied"),
            "appliedReason": applied.get("reason"),
            "effectiveResponse": applied.get("effectiveResponse"),
            "windowMs": self.window_ms,
            "profile": {
                "confidentialityThreshold": profile["confidentiality_threshold"],
                "availabilityThreshold": profile["availability_threshold"],
                "integrityThreshold": profile["integrity_threshold"],
                "prefer": profile["prefer"],
                "latencyBudgetMs": profile["latency_budget_ms"],
            },
            "scoring_factors": self._extract_scoring_factors(observation, profile),
        }

        return {
            "decision": decision,
            "delayMs": profile["delay_ms"] if decision_choice["action"] == "delay_response" else 0,
        }

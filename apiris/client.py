from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from .config import load_config
from .decision_engine import DecisionEngine
from .evaluator import ObservationEvaluator
from .interceptor import ResponseInterceptor
from .log_utils import append_jsonl
from .policy.policy_loader import PolicyLoader
from .policy.policy_manager import PolicyManager
from .ai.anomaly_model import AnomalyScorer
from .intelligence.cve_advisory import CVEAdvisorySystem, CVEAdvisory


@dataclass
class ApirisDecision:
    action: str
    tradeoff: str
    confidence: float


@dataclass
class ApirisSummary:
    cad_scores: Dict[str, float]
    mode: str
    action: str
    tradeoff: str


@dataclass
class ApirisResponse:
    data: Any
    cad_summary: ApirisSummary
    decision: ApirisDecision
    confidence: float
    status_code: Optional[int]
    headers: Dict[str, Any]
    raw: Optional[str]
    scoring_factors: Optional[Dict[str, Any]] = None
    cve_advisory: Optional[CVEAdvisory] = None


class ApirisClient:
    def __init__(self, config_path: str = "config.yaml", policy_path: Optional[str] = None) -> None:
        self.config = load_config(config_path)
        self.session = requests.Session()
        policy_manager = None
        if policy_path:
            try:
                policy = PolicyLoader().load(policy_path)
                policy_manager = PolicyManager(policy)
            except Exception:
                policy_manager = None
        self.decision_engine = DecisionEngine(self.config, policy_manager=policy_manager)
        self.interceptor = ResponseInterceptor()

        self.ai_enabled = bool(self.config.enable_ai)
        self.anomaly_scorer = None
        if self.ai_enabled:
            try:
                model_path = f"{self.config.models_dir}/anomaly_model.json"
                threshold = float(self.config.anomaly_threshold)
                self.anomaly_scorer = AnomalyScorer(model_path, soft_threshold=threshold, strong_threshold=threshold)
            except Exception:
                self.ai_enabled = False
                self.anomaly_scorer = None
        
        # Initialize CVE advisory system (optional, advisory-only)
        self.cve_system = CVEAdvisorySystem()

        self.evaluator = ObservationEvaluator(self.config, anomaly_scorer=self.anomaly_scorer if self.ai_enabled else None)

        self.log_paths = {
            "observations": f"{self.config.log_dir}/cad_observations.jsonl",
            "decisions": f"{self.config.log_dir}/cad_decisions.jsonl",
            "predictions": f"{self.config.log_dir}/cad_predictions.jsonl",
            "anomalies": f"{self.config.log_dir}/cad_anomalies.jsonl",
        }

    def get(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, timeout: float = 5.0) -> ApirisResponse:
        request_id = uuid.uuid4().hex
        started_at = time.time()
        parsed_url = urlparse(url)
        api_name = parsed_url.netloc or url
        endpoint = parsed_url.path or "/"

        response_dict: Optional[Dict[str, Any]] = None
        error: Optional[Dict[str, str]] = None
        raw_text: Optional[str] = None
        status_code: Optional[int] = None
        response_headers: Dict[str, Any] = {}

        try:
            res = self.session.get(url, params=params, headers=headers, timeout=timeout)
            raw_text = res.text
            status_code = res.status_code
            response_headers = dict(res.headers)
            response_dict = {
                "status": status_code,
                "headers": response_headers,
                "body": raw_text,
            }
        except requests.Timeout as err:
            error = {"name": "Timeout", "message": str(err)}
        except requests.RequestException as err:
            error = {"name": err.__class__.__name__, "message": str(err)}

        timing_ms = int((time.time() - started_at) * 1000)

        request_payload = {
            "method": "GET",
            "url": url,
            "headers": headers or {},
            "params": params or {},
        }

        observation = self.evaluator.evaluate(
            api=api_name,
            request=request_payload,
            response=response_dict or {},
            error=error,
            runtime_context={
                "run_id": "Apiris",
                "seq": 0,
                "interval_ms": 0,
                "duration_ms": 0,
                "soft_timeout_ms": 0,
                "timing_ms": timing_ms,
                "vs_currency": "usd",
                "request_id": request_id,
            },
        )

        parsed_body = None
        if raw_text:
            try:
                parsed_body = json.loads(raw_text)
            except json.JSONDecodeError:
                parsed_body = None

        decision_result = self.decision_engine.evaluate(
            observation=observation,
            response_text=raw_text,
            parsed=parsed_body,
            response_headers=response_headers,
            response_status=status_code,
        )
        decision = decision_result["decision"]

        effective_response = self.interceptor.apply(
            action=decision.get("action", "pass_through"),
            response_text=raw_text,
            parsed=parsed_body,
            response_headers=response_headers,
            response_status=status_code,
            cache=self.decision_engine.get_cache(api_name),
            cache_ttl_ms=self.config.cache_ttl_ms,
        )

        cad_scores = decision.get("scores", {})
        if self.ai_enabled:
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
            "mode": self.config.mode,
            "latency_ms": observation.get("availability", {}).get("latencyMs"),
            "schema_changed": observation.get("integrity", {}).get("schemaChanged"),
        }

        append_jsonl(self.log_paths["observations"], log_entry)
        append_jsonl(self.log_paths["decisions"], log_entry)
        if self.ai_enabled:
            append_jsonl(self.log_paths["predictions"], log_entry)
            append_jsonl(self.log_paths["anomalies"], log_entry)

        response_data = parsed_body if parsed_body is not None else raw_text

        cad_summary = ApirisSummary(
            cad_scores=cad_scores,
            mode=self.config.mode,
            action=decision_payload["action"],
            tradeoff=decision_payload["tradeoff"],
        )

        cad_decision = ApirisDecision(**decision_payload)
        
        # Get scoring factors for transparency
        scoring_factors = decision.get("scoring_factors")
        
        # Get CVE advisory (advisory-only, never affects runtime)
        cve_advisory = None
        if self.cve_system.enabled:
            vendor = self.cve_system.extract_vendor_from_url(url)
            if vendor:
                cve_advisory = self.cve_system.get_advisory(vendor)

        return ApirisResponse(
            data=response_data,
            cad_summary=cad_summary,
            decision=cad_decision,
            confidence=cad_decision.confidence,
            status_code=status_code,
            headers=response_headers,
            raw=effective_response.get("body") if isinstance(effective_response, dict) else raw_text,
            scoring_factors=scoring_factors,
            cve_advisory=cve_advisory,
        )

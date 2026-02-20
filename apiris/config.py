from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


@dataclass
class ApirisConfig:
    enable_ai: bool = True
    integrity_threshold: float = 0.0
    availability_threshold: float = 0.0
    anomaly_threshold: float = 0.0
    mode: str = "enforce"
    enable_explanation: bool = False
    log_dir: str = "runtime/logs"
    models_dir: str = "models"
    window_ms: int = 300000
    cache_ttl_ms: int = 300000
    latency_budget_ms: int = 1000

    @property
    def confidentiality_threshold(self) -> float:
        return self.integrity_threshold


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        return {}
    return data


def load_config(path: str = "config.yaml") -> ApirisConfig:
    config_path = Path(path)
    raw = _load_yaml(config_path)
    Apiris = raw.get("Apiris", {}) if isinstance(raw, dict) else {}
    if not isinstance(Apiris, dict):
        Apiris = {}

    defaults = ApirisConfig()

    mode = str(Apiris.get("mode", defaults.mode)).lower()
    if mode not in {"passive", "enforce", "strict"}:
        mode = defaults.mode

    def safe_float(value: Any, fallback: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return fallback

    def safe_int(value: Any, fallback: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return fallback

    return ApirisConfig(
        enable_ai=bool(Apiris.get("enable_ai", defaults.enable_ai)),
        integrity_threshold=safe_float(Apiris.get("integrity_threshold"), defaults.integrity_threshold),
        availability_threshold=safe_float(Apiris.get("availability_threshold"), defaults.availability_threshold),
        anomaly_threshold=safe_float(Apiris.get("anomaly_threshold"), defaults.anomaly_threshold),
        mode=mode,
        enable_explanation=bool(Apiris.get("enable_explanation", defaults.enable_explanation)),
        log_dir=str(Apiris.get("log_dir", defaults.log_dir)),
        models_dir=str(Apiris.get("models_dir", defaults.models_dir)),
        window_ms=safe_int(Apiris.get("window_ms"), defaults.window_ms),
        cache_ttl_ms=safe_int(Apiris.get("cache_ttl_ms"), defaults.cache_ttl_ms),
        latency_budget_ms=safe_int(Apiris.get("latency_budget_ms"), defaults.latency_budget_ms),
    )

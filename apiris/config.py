from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


@dataclass
class ApirisConfig:
    enable_ai: bool = True
    strict_zero_tolerance: bool = False
    integrity_threshold: float = 0.40
    availability_threshold: float = 0.40
    anomaly_threshold: float = 0.70
    hysteresis_band: float = 0.05
    mode: str = "enforce"
    enable_explanation: bool = False
    log_dir: str = "runtime/logs"
    models_dir: str = "models"
    window_ms: int = 300000
    cache_ttl_ms: int = 300000
    latency_budget_ms: int = 1000

    def __post_init__(self) -> None:
        if self.strict_zero_tolerance:
            # Revert to legacy 0.0 thresholds for backward compatibility
            # only if not explicitly overridden to another custom value
            if self.integrity_threshold == 0.40:
                self.integrity_threshold = 0.0
            if self.availability_threshold == 0.40:
                self.availability_threshold = 0.0
            if self.anomaly_threshold == 0.70:
                self.anomaly_threshold = 0.0

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
    
    # Support case-insensitive root key ('apiris' or 'Apiris')
    cfg_data = {}
    if isinstance(raw, dict):
        cfg_data = raw.get("apiris") or raw.get("Apiris") or {}
    if not isinstance(cfg_data, dict):
        cfg_data = {}

    strict_zero_tolerance = bool(cfg_data.get("strict_zero_tolerance", False))
    defaults = ApirisConfig(strict_zero_tolerance=strict_zero_tolerance)

    mode = str(cfg_data.get("mode", defaults.mode)).lower()
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
        enable_ai=bool(cfg_data.get("enable_ai", defaults.enable_ai)),
        strict_zero_tolerance=strict_zero_tolerance,
        integrity_threshold=safe_float(cfg_data.get("integrity_threshold"), defaults.integrity_threshold),
        availability_threshold=safe_float(cfg_data.get("availability_threshold"), defaults.availability_threshold),
        anomaly_threshold=safe_float(cfg_data.get("anomaly_threshold"), defaults.anomaly_threshold),
        hysteresis_band=safe_float(cfg_data.get("hysteresis_band"), defaults.hysteresis_band),
        mode=mode,
        enable_explanation=bool(cfg_data.get("enable_explanation", defaults.enable_explanation)),
        log_dir=str(cfg_data.get("log_dir", defaults.log_dir)),
        models_dir=str(cfg_data.get("models_dir", defaults.models_dir)),
        window_ms=safe_int(cfg_data.get("window_ms"), defaults.window_ms),
        cache_ttl_ms=safe_int(cfg_data.get("cache_ttl_ms"), defaults.cache_ttl_ms),
        latency_budget_ms=safe_int(cfg_data.get("latency_budget_ms"), defaults.latency_budget_ms),
    )

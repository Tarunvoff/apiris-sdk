from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class EffectivePolicy:
    values: Dict[str, Any]


class PolicyManager:
    def __init__(self, policy: Optional[Dict[str, Any]] = None) -> None:
        self.policy = policy or {"global": {}, "services": {}, "endpoints": {}}

    def get_effective_policy(self, service_name: str, endpoint: Optional[str] = None) -> EffectivePolicy:
        merged: Dict[str, Any] = {}
        merged.update(self.policy.get("global") or {})
        merged.update((self.policy.get("services") or {}).get(service_name, {}))
        if endpoint:
            merged.update(((self.policy.get("endpoints") or {}).get(service_name, {}) or {}).get(endpoint, {}))
        return EffectivePolicy(values=merged)

    def apply_to_profile(self, profile: Dict[str, Any], service_name: str, endpoint: Optional[str] = None) -> Dict[str, Any]:
        effective = self.get_effective_policy(service_name, endpoint).values
        if not effective:
            return profile

        allowed_keys = {
            "confidentiality_threshold": "confidentiality_threshold",
            "availability_threshold": "availability_threshold",
            "integrity_threshold": "integrity_threshold",
            "confidentiality_weight": "confidentiality_weight",
            "availability_weight": "availability_weight",
            "integrity_weight": "integrity_weight",
            "latency_budget_ms": "latency_budget_ms",
            "delay_ms": "delay_ms",
            "prefer": "prefer",
        }

        updated = profile.copy()
        for key, target in allowed_keys.items():
            if key in effective and effective[key] is not None:
                updated[target] = effective[key]

        if effective.get("force_integrity_priority") is True:
            updated["prefer"] = "integrity"

        return updated

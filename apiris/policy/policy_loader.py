from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import yaml

from .policy_validator import PolicyValidator


class PolicyLoader:
    def __init__(self, validator: PolicyValidator | None = None) -> None:
        self.validator = validator or PolicyValidator()

    def load(self, path: str) -> Dict[str, Any]:
        policy_path = Path(path)
        if not policy_path.exists():
            return {}
        if policy_path.suffix.lower() in {".yaml", ".yml"}:
            raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        else:
            raw = json.loads(policy_path.read_text(encoding="utf-8"))

        policy = self._normalize(raw)
        self.validator.validate(policy)
        return policy

    def _normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {}
        if "policy" in raw and isinstance(raw["policy"], dict):
            return {"global": {}, "services": {raw["policy"].get("service") or "default": raw["policy"]}, "endpoints": {}}
        if "policies" in raw and isinstance(raw["policies"], list):
            policy: Dict[str, Any] = {"global": {}, "services": {}, "endpoints": {}}
            for entry in raw["policies"]:
                if not isinstance(entry, dict):
                    continue
                scope = entry.get("scope", "service")
                if scope == "global":
                    policy["global"] = entry
                elif scope == "endpoint":
                    service = entry.get("service") or "default"
                    endpoint = entry.get("endpoint") or "/"
                    policy["endpoints"].setdefault(service, {})[endpoint] = entry
                else:
                    service = entry.get("service") or "default"
                    policy["services"][service] = entry
            return policy

        normalized: Dict[str, Any] = {"global": {}, "services": {}, "endpoints": {}}
        if "global" in raw:
            normalized["global"] = raw.get("global") or {}
        if "services" in raw:
            normalized["services"] = raw.get("services") or {}
        if "endpoints" in raw:
            normalized["endpoints"] = raw.get("endpoints") or {}
        return normalized

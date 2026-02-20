from __future__ import annotations

from typing import Any, Dict


class PolicyValidator:
    def validate(self, policy: Dict[str, Any]) -> None:
        if not isinstance(policy, dict):
            raise ValueError("Policy must be a dictionary")
        for scope in ("global", "services", "endpoints"):
            if scope not in policy:
                policy[scope] = {}

        def validate_policy_entry(entry: Dict[str, Any]) -> None:
            for key in ("integrity_threshold", "availability_threshold", "confidentiality_threshold"):
                if key in entry:
                    value = entry[key]
                    if not isinstance(value, (int, float)):
                        raise ValueError(f"Policy {key} must be numeric")
                    if value < 0 or value > 1:
                        raise ValueError(f"Policy {key} must be between 0 and 1")
            if "prefer" in entry and entry["prefer"] not in {"availability", "integrity"}:
                raise ValueError("Policy prefer must be 'availability' or 'integrity'")

        if isinstance(policy.get("global"), dict):
            validate_policy_entry(policy["global"])
        if isinstance(policy.get("services"), dict):
            for entry in policy["services"].values():
                if isinstance(entry, dict):
                    validate_policy_entry(entry)
        if isinstance(policy.get("endpoints"), dict):
            for service in policy["endpoints"].values():
                if isinstance(service, dict):
                    for entry in service.values():
                        if isinstance(entry, dict):
                            validate_policy_entry(entry)

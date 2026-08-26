from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ServiceProfile


DEGRADATION_ACTIONS = {
    "serve_stale_cache",
    "downgrade_fidelity",
    "delay_response",
    "mask_sensitive_fields",
}
REJECTION_ACTIONS = {"reject_response", "block"}


class RiskAggregator:
    """
    Aggregates runtime CAD decision logs into service risk profiles.
    """

    def __init__(self, log_path: str, store: Optional[Any] = None) -> None:
        self.log_path = log_path
        self.store = store

    def aggregate(self) -> List[ServiceProfile]:
        path = Path(self.log_path)
        if not path.exists():
            return []

        by_service: Dict[str, List[Dict[str, Any]]] = {}
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        service = entry.get("service_name") or entry.get("api") or "unknown"
                        by_service.setdefault(service, []).append(entry)
        except Exception:
            return []

        profiles: List[ServiceProfile] = []

        for service, entries in by_service.items():
            if not entries:
                continue

            total = len(entries)
            c_scores = [e.get("cad_scores", {}).get("C_score", 1.0) for e in entries]
            a_scores = [e.get("cad_scores", {}).get("A_score", 1.0) for e in entries]
            d_scores = [e.get("cad_scores", {}).get("D_score", 1.0) for e in entries]

            actions = [
                e.get("decision", {}).get("action")
                if isinstance(e.get("decision"), dict)
                else e.get("decision_action")
                for e in entries
            ]

            degraded_count = sum(1 for a in actions if a in DEGRADATION_ACTIONS)
            rejected_count = sum(1 for a in actions if a in REJECTION_ACTIONS)

            latest_ts = entries[-1].get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            profile = ServiceProfile(
                service_name=service,
                avg_c_score=sum(c_scores) / total,
                avg_a_score=sum(a_scores) / total,
                avg_d_score=sum(d_scores) / total,
                degradation_frequency=degraded_count / total,
                rejection_frequency=rejected_count / total,
                sample_count=total,
                updated_at=latest_ts,
            )

            if self.store and hasattr(self.store, "upsert_service_profile"):
                try:
                    self.store.upsert_service_profile(profile)
                except Exception:
                    pass

            profiles.append(profile)

        return profiles

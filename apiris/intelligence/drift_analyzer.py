from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import DriftAlert


class DriftAnalyzer:
    """
    Lightweight windowed drift analyzer for API CAD reliability and performance.
    """

    def __init__(
        self,
        window_size: int = 5,
        cad_drift_threshold: float = 0.2,
        latency_std_threshold_ms: float = 100.0,
        schema_change_threshold: float = 0.2,
    ) -> None:
        self.window_size = window_size
        self.cad_drift_threshold = cad_drift_threshold
        self.latency_std_threshold_ms = latency_std_threshold_ms
        self.schema_change_threshold = schema_change_threshold

    def analyze(self, log_path: str) -> List[DriftAlert]:
        path = Path(log_path)
        if not path.exists():
            return []

        entries: List[Dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception:
            return []

        if not entries:
            return []

        by_service: Dict[str, List[Dict[str, Any]]] = {}
        for entry in entries:
            service = entry.get("service_name") or entry.get("api") or "unknown"
            by_service.setdefault(service, []).append(entry)

        alerts: List[DriftAlert] = []

        for service, s_entries in by_service.items():
            if len(s_entries) < self.window_size * 2:
                # Need at least two windows to compare baseline vs current
                continue

            baseline_window = s_entries[: self.window_size]
            current_window = s_entries[-self.window_size :]
            last_ts = current_window[-1].get("timestamp", "")

            # CAD Pillar score deltas
            pillars = [
                ("confidentiality", "C_score"),
                ("availability", "A_score"),
                ("integrity", "D_score"),
            ]

            for pillar_name, key in pillars:
                base_vals = [e.get("cad_scores", {}).get(key, 1.0) for e in baseline_window]
                curr_vals = [e.get("cad_scores", {}).get(key, 1.0) for e in current_window]
                base_avg = sum(base_vals) / len(base_vals) if base_vals else 1.0
                curr_avg = sum(curr_vals) / len(curr_vals) if curr_vals else 1.0
                delta = abs(base_avg - curr_avg)

                if delta >= self.cad_drift_threshold:
                    alerts.append(
                        DriftAlert(
                            service_name=service,
                            pillar=pillar_name,
                            metric=key,
                            delta=round(delta, 3),
                            threshold=self.cad_drift_threshold,
                            timestamp=last_ts,
                            message=f"{pillar_name.capitalize()} drift of {delta:.2f} exceeded threshold {self.cad_drift_threshold:.2f}",
                        )
                    )

            # Latency standard deviation drift
            curr_latencies = [e.get("latency_ms", 0) for e in current_window if e.get("latency_ms") is not None]
            if len(curr_latencies) > 1:
                mean_lat = sum(curr_latencies) / len(curr_latencies)
                var_lat = sum((x - mean_lat) ** 2 for x in curr_latencies) / len(curr_latencies)
                std_lat = math.sqrt(var_lat)
                if std_lat >= self.latency_std_threshold_ms:
                    alerts.append(
                        DriftAlert(
                            service_name=service,
                            pillar="availability",
                            metric="latency_std_ms",
                            delta=round(std_lat, 2),
                            threshold=self.latency_std_threshold_ms,
                            timestamp=last_ts,
                            message=f"Latency standard deviation {std_lat:.2f}ms exceeded threshold {self.latency_std_threshold_ms:.2f}ms",
                        )
                    )

            # Schema change frequency
            schema_changes = [1 if e.get("schema_changed") else 0 for e in current_window]
            schema_rate = sum(schema_changes) / len(schema_changes) if schema_changes else 0.0
            if schema_rate >= self.schema_change_threshold:
                alerts.append(
                    DriftAlert(
                        service_name=service,
                        pillar="integrity",
                        metric="schema_change_rate",
                        delta=round(schema_rate, 2),
                        threshold=self.schema_change_threshold,
                        timestamp=last_ts,
                        message=f"Schema change rate {schema_rate:.2f} exceeded threshold {self.schema_change_threshold:.2f}",
                    )
                )

        return alerts

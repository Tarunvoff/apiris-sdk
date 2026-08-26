from __future__ import annotations

import time
from typing import Optional

from .models import VendorProfile


class VendorProfileBuilder:
    """
    Builds vendor risk & trust profiles from stability, incident, and recovery metrics.
    """

    def compute_trust_score(
        self,
        integrity_stability: float,
        availability_stability: float,
        incident_frequency: float,
        recovery_speed: float,
    ) -> float:
        # Weighted combination of stability and resilience metrics
        raw_score = (
            0.35 * integrity_stability
            + 0.35 * availability_stability
            + 0.15 * max(0.0, 1.0 - incident_frequency)
            + 0.15 * recovery_speed
        )
        return max(0.0, min(1.0, raw_score))

    def build_profile(
        self,
        vendor_name: str,
        integrity_stability: float,
        availability_stability: float,
        incident_frequency: float,
        recovery_speed: float,
        updated_at: Optional[str] = None,
    ) -> VendorProfile:
        trust_score = self.compute_trust_score(
            integrity_stability=integrity_stability,
            availability_stability=availability_stability,
            incident_frequency=incident_frequency,
            recovery_speed=recovery_speed,
        )

        return VendorProfile(
            vendor_name=vendor_name,
            vendor_trust_score=trust_score,
            integrity_stability=integrity_stability,
            availability_stability=availability_stability,
            incident_frequency=incident_frequency,
            recovery_speed=recovery_speed,
            updated_at=updated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

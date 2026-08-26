from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceProfile:
    service_name: str
    avg_c_score: float
    avg_a_score: float
    avg_d_score: float
    degradation_frequency: float
    rejection_frequency: float
    sample_count: int
    updated_at: str


@dataclass
class VendorProfile:
    vendor_name: str
    vendor_trust_score: float
    integrity_stability: float
    availability_stability: float
    incident_frequency: float
    recovery_speed: float
    updated_at: Optional[str] = None


@dataclass
class DriftAlert:
    service_name: str
    pillar: str
    metric: str
    delta: float
    threshold: float
    timestamp: str
    message: str

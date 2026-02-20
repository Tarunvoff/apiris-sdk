"""Intelligence plane modules."""

# Note: Some modules temporarily disabled due to missing dependencies
# from .models import ServiceProfile, VendorProfile
# from .risk_aggregator import RiskAggregator
# from .vendor_profile import VendorProfileBuilder
# from .drift_analyzer import DriftAnalyzer, DriftAlert
# from .time_series_store import CadTimeSeriesStore

# CVE advisory system is standalone and fully functional
from .cve_advisory import CVEAdvisorySystem, CVEAdvisory, CVEEntry

__all__ = [
    # "ServiceProfile",
    # "VendorProfile",
    # "RiskAggregator",
    # "VendorProfileBuilder",
    # "DriftAnalyzer",
    # "DriftAlert",
    # "CadTimeSeriesStore",
    "CVEAdvisorySystem",
    "CVEAdvisory",
    "CVEEntry",
]

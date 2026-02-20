"""
CVE Advisory System - Local, offline vulnerability intelligence

This module provides advisory-only CVE information without modifying runtime decisions.
All CVE data is loaded from local JSON files - no external API calls.

ARCHITECTURE GUARANTEES:
- Advisory only: CVE scores never affect decision engine
- Fully offline: No external API calls
- Deterministic: Same input always gives same output
- Non-blocking: CVE lookup failures never break runtime
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CVEEntry:
    """Represents a single CVE entry"""
    id: str
    description: str
    severity: str
    score: float
    published_date: str
    affected_versions: List[str]
    references: List[str]


@dataclass
class CVEAdvisory:
    """Advisory CVE information for a vendor/service"""
    vendor: str
    service: str
    cve_entries: List[CVEEntry]
    advisory_score: float
    risk_level: str
    total_cves: int


class CVEAdvisorySystem:
    """
    Local CVE advisory system.
    
    Loads CVE data from local JSON file and provides advisory information
    for vendor/service combinations. Never modifies runtime decisions.
    """
    
    def __init__(self, cve_data_path: str = "models/cve_data.json"):
        """
        Initialize CVE advisory system.
        
        Args:
            cve_data_path: Path to local CVE database JSON file
        """
        self.cve_data: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        self.enabled = False
        self._load_cve_data(cve_data_path)
    
    def _load_cve_data(self, path: str) -> None:
        """Load CVE data from local JSON file."""
        try:
            cve_path = Path(path)
            if not cve_path.exists():
                # CVE system is optional - silently disable if file not found
                return
            
            with open(cve_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.cve_data = data.get("vendors", {})
                self.enabled = True
        except Exception:
            # Never fail - CVE is advisory only
            self.enabled = False
    
    def _compute_advisory_score(self, cve_entries: List[CVEEntry]) -> float:
        """
        Compute an advisory severity score from CVE entries.
        
        Returns a score from 0.0 (no risk) to 1.0 (critical risk).
        """
        if not cve_entries:
            return 0.0
        
        # Weight by severity
        severity_weights = {
            "CRITICAL": 1.0,
            "HIGH": 0.7,
            "MEDIUM": 0.4,
            "LOW": 0.1
        }
        
        total_weight = sum(severity_weights.get(cve.severity, 0.0) for cve in cve_entries)
        max_weight = len(cve_entries) * 1.0  # Max if all were CRITICAL
        
        return min(1.0, total_weight / max_weight) if max_weight > 0 else 0.0
    
    def _classify_risk(self, advisory_score: float, total_cves: int) -> str:
        """
        Classify risk level based on advisory score and CVE count.
        
        Returns: LOW, MODERATE, HIGH, or CRITICAL
        """
        if advisory_score >= 0.8 and total_cves >= 5:
            return "CRITICAL"
        elif advisory_score >= 0.6 or total_cves >= 10:
            return "HIGH"
        elif advisory_score >= 0.3 or total_cves >= 3:
            return "MODERATE"
        else:
            return "LOW"
    
    def get_advisory(self, vendor: str, service: Optional[str] = None) -> Optional[CVEAdvisory]:
        """
        Get CVE advisory for a vendor/service.
        
        Args:
            vendor: Vendor name (e.g., "openai", "anthropic", "google")
            service: Optional service name (e.g., "gpt-4", "claude-3")
        
        Returns:
            CVEAdvisory if CVE data found, None otherwise
        """
        if not self.enabled:
            return None
        
        # Normalize vendor name
        vendor_key = vendor.lower().replace("-", "").replace("_", "")
        
        # Try exact vendor match
        vendor_data = self.cve_data.get(vendor_key)
        if not vendor_data:
            # Try substring match
            for key in self.cve_data:
                if vendor_key in key or key in vendor_key:
                    vendor_data = self.cve_data[key]
                    break
        
        if not vendor_data:
            return None
        
        # Support both old and new data structures
        # New structure: {"critical_count": X, "high_count": Y, "recent_cves": [...]}
        # Old structure: {"all": [...], "service_name": [...]}
        cve_list = None
        
        if "recent_cves" in vendor_data:
            # New structure with recent_cves
            cve_list = vendor_data["recent_cves"]
        else:
            # Old structure with service-specific or "all" key
            service_key = service.lower().replace("-", "").replace("_", "") if service else "all"
            cve_list = vendor_data.get(service_key, vendor_data.get("all", []))
        
        if not cve_list:
            return None
        
        # Convert to CVEEntry objects with support for both field name variations
        cve_entries = [
            CVEEntry(
                id=cve.get("id", ""),
                description=cve.get("description", f"Security vulnerability {cve.get('severity', 'UNKNOWN')} - {cve.get('id', '')}"),
                severity=cve.get("severity", "UNKNOWN"),
                score=float(cve.get("score") or cve.get("cvss") or 0.0),  # Handle None values
                published_date=cve.get("published_date", cve.get("published", "")),  # Support both field names
                affected_versions=cve.get("affected_versions", []),
                references=cve.get("references", [])
            )
            for cve in cve_list
        ]
        
        # Compute advisory metrics
        advisory_score = self._compute_advisory_score(cve_entries)
        risk_level = self._classify_risk(advisory_score, len(cve_entries))
        
        return CVEAdvisory(
            vendor=vendor,
            service=service or "all",
            cve_entries=cve_entries,
            advisory_score=advisory_score,
            risk_level=risk_level,
            total_cves=len(cve_entries)
        )
    
    def extract_vendor_from_url(self, url: str) -> Optional[str]:
        """
        Extract vendor name from URL.
        
        Args:
            url: API endpoint URL
        
        Returns:
            Vendor name if identifiable, None otherwise
        """
        url_lower = url.lower()
        
        # Common vendor patterns
        vendor_patterns = {
            "openai": ["openai.com", "api.openai"],
            "anthropic": ["anthropic.com", "claude"],
            "google": ["google.com", "googleapis.com"],
            "cohere": ["cohere.ai", "cohere.com"],
            "huggingface": ["huggingface.co", "hf.co"],
            "aws": ["amazonaws.com", "aws.amazon"],
            "azure": ["azure.com", "microsoft.com/azure"],
            "nvidia": ["nvidia.com", "nvcf"],
        }
        
        for vendor, patterns in vendor_patterns.items():
            if any(pattern in url_lower for pattern in patterns):
                return vendor
        
        return None

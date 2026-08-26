import json
import tempfile
from pathlib import Path
from scripts.validate_cve_data import validate_cve_database, validate_cve_entry


def test_cve_database_integrity():
    """Verify that current production CVE dataset passes full validation without errors."""
    repo_root = Path(__file__).resolve().parents[1]
    cve_path = repo_root / "apiris" / "models" / "cve_data.json"
    assert cve_path.exists(), f"Missing CVE dataset at {cve_path}"

    vendors_count, cves_count, errors = validate_cve_database(cve_path)
    assert vendors_count >= 40, f"Expected at least 40 vendors, got {vendors_count}"
    assert cves_count >= 60, f"Expected at least 60 CVEs, got {cves_count}"
    assert not errors, f"CVE validation errors encountered: {errors}"


def test_cve_misattribution_detection_ghost_anthropic():
    """Verify validator flags historical bug: Ghost CMS CVE mistagged under Anthropic."""
    bad_entry = {
        "id": "CVE-2026-26980",
        "severity": "CRITICAL",
        "score": 9.4,
        "description": "Ghost has a SQL injection in Content API",
        "references": ["https://github.com/TryGhost/Ghost/security/advisories/GHSA-w52v-v783-gw97"],
    }
    errors = validate_cve_entry("anthropic", bad_entry)
    assert any("misattribution" in err.lower() and "ghost" in err.lower() for err in errors), (
        f"Expected Ghost/Anthropic misattribution detection, got: {errors}"
    )


def test_cve_misattribution_detection_gogs_pusher():
    """Verify validator flags historical bug: Gogs git server mistagged under Pusher."""
    bad_entry = {
        "id": "CVE-2026-25232",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Gogs has a Protected Branch Deletion Bypass in Web Interface",
        "references": ["https://github.com/gogs/gogs/security/advisories/GHSA-2c6v-8r3v-gh6p"],
    }
    errors = validate_cve_entry("pusher", bad_entry)
    assert any("misattribution" in err.lower() and "gogs" in err.lower() for err in errors), (
        f"Expected Gogs/Pusher misattribution detection, got: {errors}"
    )


def test_cve_misattribution_detection_langchain_openai():
    """Verify validator flags cross-vendor misattribution: Langchain under OpenAI."""
    bad_entry = {
        "id": "CVE-2025-68665",
        "severity": "HIGH",
        "score": 8.1,
        "description": "LangChain serialization injection vulnerability enables secret extraction",
        "references": ["https://github.com/langchain-ai/langchain/security/advisories/GHSA-1234"],
    }
    errors = validate_cve_entry("openai", bad_entry)
    assert any("mismatch" in err.lower() or "misattribution" in err.lower() for err in errors), (
        f"Expected Langchain/OpenAI mismatch detection, got: {errors}"
    )


def test_cve_schema_validation_errors(tmp_path: Path):
    """Verify full database validator catches malformed schema entries."""
    malformed_dataset = {
        "vendors": {
            "anthropic": {
                "recent_cves": [
                    {
                        "id": "INVALID-ID-999",
                        "severity": "INVALID_SEVERITY",
                        "score": 15.5,  # Out of [0, 10] range
                        "description": "Ghost has a SQL injection in Content API",
                        "references": ["https://github.com/TryGhost/Ghost"],
                    }
                ]
            }
        }
    }
    bad_file = tmp_path / "bad_cve.json"
    bad_file.write_text(json.dumps(malformed_dataset), encoding="utf-8")

    vendors_count, cves_count, errors = validate_cve_database(bad_file)
    assert vendors_count == 1
    assert cves_count == 1
    assert any("id format" in e.lower() for e in errors)
    assert any("invalid severity" in e.lower() for e in errors)
    assert any("out of range" in e.lower() for e in errors)
    assert any("misattribution" in e.lower() for e in errors)

"""
Unit Tests for Calibrated Confidence Scoring and Relative Severity Ordering
"""

from pathlib import Path
import responses

from apiris.client import ApirisClient
from apiris.config import ApirisConfig
from apiris.decision_engine import DecisionEngine


def test_confidence_calibration_curve():
    config = ApirisConfig(
        integrity_threshold=0.40,
        availability_threshold=0.40,
        enable_ai=False,
    )
    engine = DecisionEngine(config)
    profile = engine._get_profile("test_api")

    # 1. Obviously clean call (far above threshold: score 1.0 vs threshold 0.40)
    clean_scores = {"C_score": 1.0, "A_score": 1.0, "D_score": 1.0, "integrityRate": 0.0}
    clean_conf = engine._compute_confidence(clean_scores, clean_scores, profile, "pass_through", ai_used=False)

    # 2. Borderline clean call (score 0.41 vs threshold 0.40)
    borderline_scores = {"C_score": 0.41, "A_score": 1.0, "D_score": 1.0, "integrityRate": 0.0}
    borderline_conf = engine._compute_confidence(borderline_scores, borderline_scores, profile, "pass_through", ai_used=False)

    # 3. Obviously malicious / critical breach (score 0.0 vs threshold 0.40)
    malicious_scores = {"C_score": 0.0, "A_score": 1.0, "D_score": 0.0, "integrityRate": 1.0}
    malicious_conf = engine._compute_confidence(malicious_scores, malicious_scores, profile, "reject_response", ai_used=False)

    assert clean_conf >= 0.95, f"Expected clean confidence >= 0.95, got {clean_conf}"
    assert malicious_conf >= 0.95, f"Expected malicious confidence >= 0.95, got {malicious_conf}"
    assert borderline_conf < 0.65, f"Expected borderline confidence < 0.65, got {borderline_conf}"
    assert clean_conf - borderline_conf >= 0.30, "Expected measurable confidence difference between clean and borderline"
    assert malicious_conf - borderline_conf >= 0.30, "Expected measurable confidence difference between malicious and borderline"


def test_confidence_relative_ordering_moderate_vs_critical():
    """
    Assert relative ordering: A severe multi-factor breach must produce strictly higher
    confidence in protective escalation than a borderline single-factor breach triggering the same action.
    """
    config = ApirisConfig(
        integrity_threshold=0.40,
        availability_threshold=0.40,
        enable_ai=False,
    )
    engine = DecisionEngine(config)
    profile = engine._get_profile("test_api")

    # Case A: Borderline breach (score 0.38, 1 single minor flag)
    borderline_breach = {
        "C_score": 0.38,
        "A_score": 1.0,
        "D_score": 1.0,
        "confidentialityRate": 1.0,
        "availabilityRate": 0.0,
        "integrityRate": 0.0,
    }
    conf_borderline = engine._compute_confidence(
        borderline_breach, borderline_breach, profile, "mask_sensitive_fields", ai_used=False
    )

    # Case B: Moderate breach (1 single header flag, score 0.0, healthy other dimensions)
    moderate_breach = {
        "C_score": 0.0,
        "A_score": 1.0,
        "D_score": 1.0,
        "confidentialityRate": 1.0,
        "availabilityRate": 0.0,
        "integrityRate": 0.0,
    }
    conf_moderate = engine._compute_confidence(
        moderate_breach, moderate_breach, profile, "mask_sensitive_fields", ai_used=False
    )

    # Case C: Critical breach (3 confidentiality factors + availability failure)
    critical_breach = {
        "C_score": 0.0,
        "A_score": 0.0,
        "D_score": 1.0,
        "confidentialityRate": 3.0,
        "availabilityRate": 1.0,
        "integrityRate": 0.0,
    }
    conf_critical = engine._compute_confidence(
        critical_breach, critical_breach, profile, "mask_sensitive_fields", ai_used=False
    )

    assert conf_critical > conf_moderate, (
        f"Critical multi-factor breach confidence ({conf_critical}) must be strictly "
        f"greater than moderate single-factor breach confidence ({conf_moderate})"
    )
    assert conf_moderate > conf_borderline, (
        f"Moderate breach confidence ({conf_moderate}) must be strictly "
        f"greater than borderline breach confidence ({conf_borderline})"
    )
    assert conf_critical >= 0.95, f"Expected critical breach confidence >= 0.95, got {conf_critical}"
    assert conf_moderate <= 0.88, f"Expected moderate single-factor breach confidence <= 0.88, got {conf_moderate}"


def test_confidence_regression_fixtures_weather_vs_nasa():
    """
    Live regression fixtures: Compare real-world MODERATE case (weather.gov style 1-header exposure)
    against CRITICAL case (nasa.gov 403 API_KEY_MISSING with 3 confidentiality factors).
    """
    client = ApirisClient()

    with responses.RequestsMock() as mock:
        # Fixture 1: weather.gov style (HTTP 200, 1 header exposure Set-Cookie)
        mock.add(
            responses.GET,
            "https://api.weather.gov",
            body='{"status": "ok"}',
            status=200,
            headers={"Content-Type": "application/json", "Set-Cookie": "session=abc"},
        )
        res_weather = client.get("https://api.weather.gov")

        # Fixture 2: nasa.gov style (HTTP 403, missing api_key, verbose error, auth hints)
        mock.add(
            responses.GET,
            "https://api.nasa.gov/planetary/apod",
            body='{"error": {"code": "API_KEY_MISSING", "message": "No api_key was supplied. Get one at https://api.nasa.gov:8080"}}',
            status=403,
            headers={"Content-Type": "application/json"},
        )
        res_nasa = client.get("https://api.nasa.gov/planetary/apod")

        assert res_weather.decision.action == "mask_sensitive_fields"
        assert res_nasa.decision.action == "mask_sensitive_fields"

        # Assert confidence on CRITICAL case is strictly higher than on MODERATE case
        assert res_nasa.confidence > res_weather.confidence, (
            f"Expected NASA 403 critical confidence ({res_nasa.confidence}) to be strictly "
            f"greater than Weather 1-header moderate confidence ({res_weather.confidence})"
        )
        assert res_weather.confidence <= 0.88, f"Expected weather confidence <= 0.88, got {res_weather.confidence}"
        assert res_nasa.confidence >= 0.95, f"Expected NASA confidence >= 0.95, got {res_nasa.confidence}"

        # Assert Risk Classification ordering: Weather is MODERATE, NASA is CRITICAL
        from apiris.cli_ui import classify_risk
        risk_w = classify_risk(
            res_weather.cad_summary.cad_scores["C_score"],
            res_weather.cad_summary.cad_scores["A_score"],
            res_weather.cad_summary.cad_scores["D_score"],
            res_weather.decision.action,
            scoring_factors=res_weather.scoring_factors,
            status_code=res_weather.status_code,
        )
        risk_n = classify_risk(
            res_nasa.cad_summary.cad_scores["C_score"],
            res_nasa.cad_summary.cad_scores["A_score"],
            res_nasa.cad_summary.cad_scores["D_score"],
            res_nasa.decision.action,
            scoring_factors=res_nasa.scoring_factors,
            status_code=res_nasa.status_code,
        )
        assert risk_w == "MODERATE", f"Expected weather risk to be MODERATE, got {risk_w}"
        assert risk_n == "CRITICAL", f"Expected NASA risk to be CRITICAL, got {risk_n}"


def test_risk_classification_all_five_tiers():
    """
    Regression verification: Assert that all five documented risk tiers
    (LOW, MODERATE, ELEVATED, HIGH, CRITICAL) are correctly assigned to their respective traffic profiles.
    """
    from apiris.cli_ui import classify_risk, get_risk_badge

    # 1. Tier: LOW (Clean traffic, pass_through, 0 negative factors)
    factors_low = {"confidentiality_factors": [], "availability_factors": [], "integrity_factors": []}
    risk_low = classify_risk(1.0, 1.0, 1.0, "pass_through", scoring_factors=factors_low, status_code=200)
    assert risk_low == "LOW"
    assert "LOW" in get_risk_badge(risk_low)

    # 2. Tier: MODERATE (1 isolated header exposure on 200 OK)
    factors_mod = {
        "confidentiality_factors": [{"name": "Exposed Headers", "impact": "negative", "details": ["Set-Cookie"]}],
        "availability_factors": [],
        "integrity_factors": [],
    }
    risk_mod = classify_risk(0.0, 1.0, 1.0, "mask_sensitive_fields", scoring_factors=factors_mod, status_code=200)
    assert risk_mod == "MODERATE"
    assert "MODERATE" in get_risk_badge(risk_mod)

    # 3. Tier: ELEVATED (2 non-critical signals or cache fallback)
    factors_elev = {
        "confidentiality_factors": [],
        "availability_factors": [
            {"name": "Transient Latency", "impact": "negative"},
            {"name": "Soft Timeout", "impact": "negative"},
        ],
        "integrity_factors": [],
    }
    risk_elev = classify_risk(1.0, 0.35, 1.0, "serve_stale_cache", scoring_factors=factors_elev, status_code=200)
    assert risk_elev == "ELEVATED"
    assert "ELEVATED" in get_risk_badge(risk_elev)

    # 4. Tier: HIGH (Substantial multi-secret leak in confidentiality)
    factors_high = {
        "confidentiality_factors": [
            {"name": "Sensitive Fields Detected", "impact": "negative", "details": ["raw:api_key"]},
            {"name": "Auth Hints in Payload", "impact": "negative", "details": ["raw:auth_token"]},
        ],
        "availability_factors": [],
        "integrity_factors": [],
    }
    risk_high = classify_risk(0.0, 1.0, 1.0, "mask_sensitive_fields", scoring_factors=factors_high, status_code=200)
    assert risk_high == "HIGH"
    assert "HIGH" in get_risk_badge(risk_high)

    # 5. Tier: CRITICAL (Multi-pillar degradation + HTTP error / rejection)
    factors_crit = {
        "confidentiality_factors": [
            {"name": "Sensitive Fields Detected", "impact": "negative"},
            {"name": "Auth Hints in Payload", "impact": "negative"},
            {"name": "Verbose Error Signals", "impact": "negative"},
        ],
        "availability_factors": [{"name": "HTTP Client Error", "value": "HTTP 403", "impact": "negative"}],
        "integrity_factors": [],
    }
    risk_crit = classify_risk(0.0, 0.0, 1.0, "mask_sensitive_fields", scoring_factors=factors_crit, status_code=403)
    assert risk_crit == "CRITICAL"
    assert "CRITICAL" in get_risk_badge(risk_crit)


def test_hysteresis_smoothing_prevents_flapping():
    config = ApirisConfig(
        integrity_threshold=0.40,
        availability_threshold=0.40,
        hysteresis_band=0.05,
        enable_ai=False,
    )
    engine = DecisionEngine(config)
    profile = engine._get_profile("test_api")

    # Case 1: Fresh state, score 0.38 is below threshold (0.40) -> action triggers
    action_1 = engine._choose_action(
        {"C_score": 0.38, "A_score": 1.0, "D_score": 1.0},
        profile,
        previous_action=None,
    )
    assert action_1["action"] == "mask_sensitive_fields"

    # Case 2: Once active, score rises to 0.42 (above 0.40, but below 0.40 + 0.05 = 0.45)
    # Hysteresis prevents premature flapping back to pass_through
    action_2 = engine._choose_action(
        {"C_score": 0.42, "A_score": 1.0, "D_score": 1.0},
        profile,
        previous_action="mask_sensitive_fields",
    )
    assert action_2["action"] == "mask_sensitive_fields"

    # Case 3: Score solidly recovers to 0.48 (above 0.45) -> releases to pass_through
    action_3 = engine._choose_action(
        {"C_score": 0.48, "A_score": 1.0, "D_score": 1.0},
        profile,
        previous_action="mask_sensitive_fields",
    )
    assert action_3["action"] == "pass_through"


def test_strict_zero_tolerance_backward_compatibility():
    # Legacy zero-tolerance flag resets defaults to 0.0
    config_legacy = ApirisConfig(strict_zero_tolerance=True)
    assert config_legacy.integrity_threshold == 0.0
    assert config_legacy.availability_threshold == 0.0
    assert config_legacy.anomaly_threshold == 0.0

    # Default v1.1.0 configuration uses calibrated non-zero thresholds
    config_v110 = ApirisConfig()
    assert config_v110.integrity_threshold == 0.40
    assert config_v110.availability_threshold == 0.40
    assert config_v110.anomaly_threshold == 0.70

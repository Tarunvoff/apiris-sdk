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

    # 2. Obviously malicious / critical breach (score 0.0 vs threshold 0.40)
    malicious_scores = {"C_score": 0.0, "A_score": 1.0, "D_score": 0.0, "integrityRate": 1.0}
    malicious_conf = engine._compute_confidence(malicious_scores, malicious_scores, profile, "reject_response", ai_used=False)

    # 3. Borderline call (score 0.41 vs threshold 0.40)
    borderline_scores = {"C_score": 0.41, "A_score": 1.0, "D_score": 1.0, "integrityRate": 0.0}
    borderline_conf = engine._compute_confidence(borderline_scores, borderline_scores, profile, "pass_through", ai_used=False)

    assert clean_conf >= 0.95, f"Expected clean confidence >= 0.95, got {clean_conf}"
    assert malicious_conf >= 0.95, f"Expected malicious confidence >= 0.95, got {malicious_conf}"
    assert borderline_conf < 0.65, f"Expected borderline confidence < 0.65, got {borderline_conf}"
    assert clean_conf - borderline_conf >= 0.30, "Expected measurable confidence difference between clean and borderline"
    assert malicious_conf - borderline_conf >= 0.30, "Expected measurable confidence difference between malicious and borderline"


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

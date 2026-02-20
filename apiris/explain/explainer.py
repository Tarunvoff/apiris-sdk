from __future__ import annotations

from typing import Any, Dict, List, Optional


def determine_primary_risk(scores: Dict[str, Any], anomaly: Optional[Dict[str, Any]], prediction: Optional[Dict[str, Any]]) -> str:
    score_entries = [
        {"pillar": "Confidentiality", "value": scores.get("C_score", 1)},
        {"pillar": "Availability", "value": scores.get("A_score", 1)},
        {"pillar": "Data Integrity", "value": scores.get("D_score", 1)},
    ]
    score_entries.sort(key=lambda item: item["value"])
    primary = score_entries[0]["pillar"]

    if anomaly and anomaly.get("anomalyFlag") == "strong":
        primary = "Data Integrity"

    if prediction:
        probs = prediction.get("probabilities", {})
        max_pred = max(probs.get("C_degrade_next_T", 0), probs.get("A_degrade_next_T", 0), probs.get("D_degrade_next_T", 0))
        if max_pred >= 0.8:
            if max_pred == probs.get("C_degrade_next_T", 0):
                primary = "Confidentiality"
            elif max_pred == probs.get("A_degrade_next_T", 0):
                primary = "Availability"
            else:
                primary = "Data Integrity"

    return primary


def build_evidence(scores: Dict[str, Any], observation: Dict[str, Any], prediction: Optional[Dict[str, Any]], anomaly: Optional[Dict[str, Any]], recommendation: Optional[Dict[str, Any]]) -> List[str]:
    evidence: List[str] = []
    if scores:
        evidence.append(f"C_score {float(scores.get('C_score', 1)):.2f}")
        evidence.append(f"A_score {float(scores.get('A_score', 1)):.2f}")
        evidence.append(f"D_score {float(scores.get('D_score', 1)):.2f}")

    integrity = observation.get("integrity", {})
    if integrity.get("schemaChanged"):
        evidence.append("Schema changed")
    if integrity.get("temporalDrift"):
        evidence.append("Temporal drift detected")
    if integrity.get("replayedPayload"):
        evidence.append("Replayed payload detected")
    if integrity.get("crossEndpointInconsistencies"):
        evidence.append("Cross-endpoint inconsistency detected")

    availability = observation.get("availability", {})
    if availability.get("rateLimited"):
        evidence.append("Rate limited")
    if availability.get("timeoutError"):
        evidence.append("Timeout error")
    if availability.get("softTimeoutExceeded"):
        evidence.append("Soft timeout exceeded")
    if availability.get("status") and availability.get("status") >= 500:
        evidence.append(f"HTTP {availability.get('status')}")

    confidentiality = observation.get("confidentiality", {})
    if confidentiality.get("sensitiveFields"):
        evidence.append("Sensitive fields present")
    if confidentiality.get("verboseErrorSignals"):
        evidence.append("Verbose error signals")
    if confidentiality.get("authHintsInPayload"):
        evidence.append("Auth hints in payload")

    if prediction and prediction.get("probabilities"):
        probs = prediction["probabilities"]
        evidence.append(f"Predicted C {float(probs.get('C_degrade_next_T', 0)):.2f}")
        evidence.append(f"Predicted A {float(probs.get('A_degrade_next_T', 0)):.2f}")
        evidence.append(f"Predicted D {float(probs.get('D_degrade_next_T', 0)):.2f}")

    if anomaly:
        evidence.append(f"Integrity anomaly score {float(anomaly.get('anomalyScore', 0)):.2f} ({anomaly.get('anomalyFlag', 'none')})")
        if anomaly.get("topFeatures"):
            names = ", ".join(feature.get("feature") for feature in anomaly.get("topFeatures", []))
            evidence.append(f"Anomaly features: {names}")

    if recommendation:
        evidence.append(f"AI recommended {recommendation.get('recommendedTradeoff')} (p={float(recommendation.get('confidence', 0)):.2f})")

    return evidence


def determine_confidence(scores: Dict[str, Any], prediction: Optional[Dict[str, Any]], anomaly: Optional[Dict[str, Any]], recommendation: Optional[Dict[str, Any]]) -> str:
    min_score = min(scores.get("C_score", 1), scores.get("A_score", 1), scores.get("D_score", 1))
    max_pred = 0.0
    if prediction and prediction.get("probabilities"):
        probs = prediction["probabilities"]
        max_pred = max(probs.get("C_degrade_next_T", 0), probs.get("A_degrade_next_T", 0), probs.get("D_degrade_next_T", 0))
    anomaly_strong = anomaly and anomaly.get("anomalyFlag") == "strong"
    agree = recommendation is None or not recommendation.get("disagreement")

    if (min_score < 0.3 or max_pred >= 0.8 or anomaly_strong) and agree:
        return "High"
    if min_score < 0.6 or max_pred >= 0.6 or (anomaly and anomaly.get("anomalyFlag") == "soft"):
        return "Medium"
    return "Low"


def summarize_event(api: str, action: str, primary_risk: str) -> str:
    action_text = f"was {action.replace('_', ' ')}" if action and action != "pass_through" else "was passed through"
    return f"The response from {api} {action_text} due to elevated {primary_risk.lower()} risk."


def build_explanation(decision: Dict[str, Any], observation: Dict[str, Any], prediction: Optional[Dict[str, Any]] = None, anomaly: Optional[Dict[str, Any]] = None, recommendation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    scores = decision.get("scores", {})
    primary_risk = determine_primary_risk(scores, anomaly, prediction)
    evidence = build_evidence(scores, observation, prediction, anomaly, recommendation)
    confidence = determine_confidence(scores, prediction, anomaly, recommendation)
    tradeoff = decision.get("tradeoff", "none")
    action = decision.get("action", "pass_through")

    return {
        "id": decision.get("id"),
        "ts": decision.get("ts"),
        "api": observation.get("api"),
        "summary": summarize_event(observation.get("api"), action, primary_risk),
        "primaryRisk": primary_risk,
        "supportingEvidence": evidence,
        "chosenTradeoff": tradeoff,
        "action": action,
        "confidence": confidence,
        "explanationText": "\n".join(
            [
                f"Summary: {summarize_event(observation.get('api'), action, primary_risk)}",
                f"Primary CAD Risk: {primary_risk}",
                f"Evidence: {'; '.join(evidence)}",
                f"Trade-Off Chosen: {tradeoff}",
                f"Confidence Level: {confidence}",
            ]
        ),
    }

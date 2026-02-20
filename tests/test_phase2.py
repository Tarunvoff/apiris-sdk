import json
from pathlib import Path

import responses

from apiris.intelligence.drift_analyzer import DriftAnalyzer
from apiris.intelligence.risk_aggregator import RiskAggregator
from apiris.intelligence.vendor_profile import VendorProfileBuilder
from apiris.policy.policy_loader import PolicyLoader
from apiris.policy.policy_manager import PolicyManager
from apiris.storage.sqlite_store import SQLiteStore
from apiris import CADClient
from apiris.config import apirisConfig
from apiris.decision_engine import DecisionEngine


def write_jsonl(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(entry) for entry in entries))


def test_risk_aggregation_accuracy(tmp_path: Path) -> None:
    log_path = tmp_path / "runtime" / "logs" / "cad_decisions.jsonl"
    entries = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "service_name": "svc1",
            "cad_scores": {"C_score": 0.8, "A_score": 0.9, "D_score": 0.7},
            "decision": {"action": "pass_through"},
        },
        {
            "timestamp": "2026-01-01T00:00:01Z",
            "service_name": "svc1",
            "cad_scores": {"C_score": 0.6, "A_score": 0.7, "D_score": 0.5},
            "decision": {"action": "serve_stale_cache"},
        },
        {
            "timestamp": "2026-01-01T00:00:02Z",
            "service_name": "svc2",
            "cad_scores": {"C_score": 0.9, "A_score": 0.95, "D_score": 0.9},
            "decision": {"action": "reject_response"},
        },
    ]
    write_jsonl(log_path, entries)

    profiles = RiskAggregator(str(log_path)).aggregate()
    svc1 = next(profile for profile in profiles if profile.service_name == "svc1")
    assert round(svc1.avg_c_score, 2) == 0.7
    assert round(svc1.degradation_frequency, 2) == 0.5
    assert round(svc1.rejection_frequency, 2) == 0.0


def test_vendor_trust_score_calculation() -> None:
    builder = VendorProfileBuilder()
    profile = builder.build_profile(
        vendor_name="vendor-a",
        integrity_stability=0.9,
        availability_stability=0.8,
        incident_frequency=0.1,
        recovery_speed=0.7,
    )
    assert 0.0 <= profile.vendor_trust_score <= 1.0
    assert round(profile.vendor_trust_score, 2) == round(builder.compute_trust_score(0.9, 0.8, 0.1, 0.7), 2)


def test_drift_detection_trigger(tmp_path: Path) -> None:
    log_path = tmp_path / "runtime" / "logs" / "cad_decisions.jsonl"
    entries = []
    for i in range(10):
        entries.append(
            {
                "timestamp": f"2026-01-01T00:00:0{i}Z",
                "service_name": "svc1",
                "cad_scores": {"C_score": 0.9, "A_score": 0.9, "D_score": 0.9},
                "latency_ms": 50,
                "schema_changed": False,
            }
        )
    for i in range(10, 20):
        entries.append(
            {
                "timestamp": f"2026-01-01T00:00:{i}Z",
                "service_name": "svc1",
                "cad_scores": {"C_score": 0.5, "A_score": 0.5, "D_score": 0.5},
                "latency_ms": 400,
                "schema_changed": True,
            }
        )
    write_jsonl(log_path, entries)

    analyzer = DriftAnalyzer(window_size=5, cad_drift_threshold=0.2, latency_std_threshold_ms=100, schema_change_threshold=0.2)
    alerts = analyzer.analyze(str(log_path))
    assert alerts
    assert any(alert.pillar in {"confidentiality", "availability", "integrity"} for alert in alerts)


def test_policy_override_logic(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
policies:
  - scope: global
    integrity_threshold: 0.3
  - scope: service
    service: svc1
    availability_threshold: 0.4
  - scope: endpoint
    service: svc1
    endpoint: /v1
    confidentiality_threshold: 0.2
"""
    )
    loader = PolicyLoader()
    policy = loader.load(str(policy_path))
    manager = PolicyManager(policy)

    profile = {
        "confidentiality_threshold": 0.8,
        "availability_threshold": 0.8,
        "integrity_threshold": 0.8,
        "prefer": "availability",
    }
    updated = manager.apply_to_profile(profile, "svc1", "/v1")
    assert updated["integrity_threshold"] == 0.3
    assert updated["availability_threshold"] == 0.4
    assert updated["confidentiality_threshold"] == 0.2


def test_sqlite_persistence_correctness(tmp_path: Path) -> None:
    db_path = tmp_path / "Apiris.db"
    store = SQLiteStore(str(db_path))

    from apiris.intelligence.models import ServiceProfile

    profile = ServiceProfile(
        service_name="svc1",
        avg_c_score=0.7,
        avg_a_score=0.8,
        avg_d_score=0.9,
        degradation_frequency=0.1,
        rejection_frequency=0.0,
        sample_count=10,
        updated_at="2026-01-01T00:00:00Z",
    )
    store.upsert_service_profile(profile)
    loaded = store.get_service_profile("svc1")
    assert loaded
    assert loaded.avg_d_score == 0.9

    store.insert_policy_version("v1", {"global": {"integrity_threshold": 0.4}})
    policies = store.list_policy_versions()
    assert policies


def test_runtime_unaffected_by_intelligence_failure(tmp_path: Path, monkeypatch) -> None:
    def _raise(*args, **kwargs):
        raise RuntimeError("should_not_run")

    monkeypatch.setattr("Apiris.intelligence.risk_aggregator.RiskAggregator.aggregate", _raise)
    monkeypatch.setattr("Apiris.intelligence.drift_analyzer.DriftAnalyzer.analyze", _raise)

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        json.dumps(
            {
                "Apiris": {
                    "enable_ai": False,
                    "integrity_threshold": 0.25,
                    "availability_threshold": 0.4,
                    "anomaly_threshold": 0.7,
                    "mode": "enforce",
                    "log_dir": str(tmp_path / "runtime" / "logs"),
                }
            }
        )
    )

    with responses.RequestsMock() as mock:
        mock.add(responses.GET, "https://example.com", json={"ok": True}, status=200)
        client = CADClient(config_path=str(config_path))
        response = client.get("https://example.com")

    assert response.decision.action == "pass_through"


def test_policy_load_failure_falls_back_to_defaults(tmp_path: Path) -> None:
    policy_path = tmp_path / "bad_policy.yaml"
    policy_path.write_text("policies: not-a-list")

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        json.dumps(
            {
                "Apiris": {
                    "enable_ai": False,
                    "integrity_threshold": 0.25,
                    "availability_threshold": 0.4,
                    "anomaly_threshold": 0.7,
                    "mode": "enforce",
                    "log_dir": str(tmp_path / "runtime" / "logs"),
                }
            }
        )
    )

    with responses.RequestsMock() as mock:
        mock.add(responses.GET, "https://example.com", json={"ok": True}, status=200)
        client = CADClient(config_path=str(config_path), policy_path=str(policy_path))
        response = client.get("https://example.com")

    assert response.decision.action == "pass_through"


def test_db_failure_does_not_crash_aggregation(tmp_path: Path) -> None:
    class FailingStore:
        def upsert_service_profile(self, profile):
            raise RuntimeError("db offline")

    log_path = tmp_path / "runtime" / "logs" / "cad_decisions.jsonl"
    entries = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "service_name": "svc1",
            "cad_scores": {"C_score": 0.8, "A_score": 0.9, "D_score": 0.7},
            "decision": {"action": "pass_through"},
        }
    ]
    write_jsonl(log_path, entries)

    profiles = RiskAggregator(str(log_path), store=FailingStore()).aggregate()
    assert profiles


def test_drift_analyzer_does_not_mutate_thresholds(tmp_path: Path) -> None:
    log_path = tmp_path / "runtime" / "logs" / "cad_decisions.jsonl"
    entries = []
    for i in range(10):
        entries.append(
            {
                "timestamp": f"2026-01-01T00:00:0{i}Z",
                "service_name": "svc1",
                "cad_scores": {"C_score": 0.9, "A_score": 0.9, "D_score": 0.9},
                "latency_ms": 50,
                "schema_changed": False,
            }
        )
    write_jsonl(log_path, entries)

    config = ApirisConfig(integrity_threshold=0.5, availability_threshold=0.6, enable_ai=False)
    engine = DecisionEngine(config)
    analyzer = DriftAnalyzer(window_size=5)
    analyzer.analyze(str(log_path))

    assert engine.config.integrity_threshold == 0.5
    assert engine.config.availability_threshold == 0.6

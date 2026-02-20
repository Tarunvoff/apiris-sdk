import json
from pathlib import Path

import responses

from apiris import CADClient


NASA_URL = "https://api.nasa.gov/planetary/apod?api_key=Y8J2mcPKdhjVjUSSYdSGkjuXkaAouZrd6mIE6yYC"
SIMPLE_URL = "https://coingecko-simple-price"
MARKETS_URL = "https://coingecko-markets"
STRICT_URL = "https://strict-mode-api"


def write_config(path: Path, **overrides) -> Path:
    config = {
        "Apiris": {
            "enable_ai": False,
            "integrity_threshold": 0.25,
            "availability_threshold": 0.40,
            "anomaly_threshold": 0.70,
            "mode": "enforce",
            "enable_explanation": False,
            "log_dir": str(path / "runtime" / "logs"),
            "models_dir": str(path / "models"),
            "window_ms": 300000,
            "cache_ttl_ms": 300000,
            "latency_budget_ms": 1000,
        }
    }
    config["Apiris"].update(overrides)
    config_path = path / "config.yaml"
    config_path.write_text(json.dumps(config))
    return config_path


def read_jsonl(path: Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@responses.activate
def test_clean_pass_through(tmp_path: Path):
    config_path = write_config(tmp_path, enable_ai=False, mode="enforce")
    responses.add(
        responses.GET,
        NASA_URL,
        json={"status": "ok"},
        status=200,
    )

    client = CADClient(config_path=str(config_path))
    response = client.get(NASA_URL)

    assert response.data == {"status": "ok"}
    assert response.decision.action == "pass_through"
    assert response.decision.tradeoff == "none"
    assert response.decision.confidence == 1.0

    log_path = Path(tmp_path / "runtime" / "logs" / "cad_observations.jsonl")
    entries = read_jsonl(log_path)
    assert entries


@responses.activate
def test_integrity_violation(tmp_path: Path):
    config_path = write_config(tmp_path, integrity_threshold=0.6, availability_threshold=0.4, enable_ai=False)
    responses.add(responses.GET, SIMPLE_URL, json={"btc": {"usd": 1}}, status=200)
    responses.add(responses.GET, MARKETS_URL, json=[{"id": "btc", "current_price": 2}], status=200)
    responses.add(responses.GET, SIMPLE_URL, json={"btc": {"usd": 3}, "eth": {"usd": 4}}, status=200)

    client = CADClient(config_path=str(config_path))
    client.get(SIMPLE_URL)
    client.get(MARKETS_URL)
    response = client.get(SIMPLE_URL)

    assert response.decision.action == "reject_response"
    assert response.decision.tradeoff == "integrity_over_availability"
    assert response.decision.confidence > 0.7


@responses.activate
def test_strict_mode_enforcement(tmp_path: Path):
    config_path = write_config(tmp_path, mode="strict", integrity_threshold=0.6, availability_threshold=0.8)
    responses.add(responses.GET, STRICT_URL, json={"ok": True}, status=500)
    responses.add(responses.GET, STRICT_URL, json={"ok": False, "reason": "drift"}, status=500)

    client = CADClient(config_path=str(config_path))
    client.get(STRICT_URL)
    response = client.get(STRICT_URL)

    assert response.decision.action == "reject_response"
    assert response.decision.tradeoff == "integrity_over_availability"


@responses.activate
def test_ai_disabled_mode(tmp_path: Path):
    config_path = write_config(tmp_path, enable_ai=False)
    responses.add(responses.GET, NASA_URL, json={"ok": True}, status=200)

    client = CADClient(config_path=str(config_path))
    client.get(NASA_URL)

    log_path = Path(tmp_path / "runtime" / "logs" / "cad_decisions.jsonl")
    entries = read_jsonl(log_path)
    assert entries
    assert entries[-1]["ai_signals"] == {"enabled": False}

    predictions_path = Path(tmp_path / "runtime" / "logs" / "cad_predictions.jsonl")
    anomalies_path = Path(tmp_path / "runtime" / "logs" / "cad_anomalies.jsonl")
    assert not predictions_path.exists()
    assert not anomalies_path.exists()


@responses.activate
def test_logging_integrity(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    config_path = write_config(tmp_path, enable_ai=True, models_dir=str(repo_root / "models"))
    responses.add(responses.GET, NASA_URL, json={"ok": True}, status=200)

    client = CADClient(config_path=str(config_path))
    client.get(NASA_URL)

    log_dir = Path(tmp_path / "runtime" / "logs")
    observation_entries = read_jsonl(log_dir / "cad_observations.jsonl")
    decision_entries = read_jsonl(log_dir / "cad_decisions.jsonl")

    assert observation_entries
    assert decision_entries
    assert "event_id" in observation_entries[-1]

    for log_file in log_dir.glob("*.jsonl"):
        assert "baseline" not in log_file.name
        assert "adaptive" not in log_file.name


if __name__ == "__main__":
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as temp_dir:
        base = Path(temp_dir)
        config_path = write_config(base)

        with responses.RequestsMock() as mock:
            mock.add(
                responses.GET,
                "https://api.nasa.gov/planetary/apod?api_key=Y8J2mcPKdhjVjUSSYdSGkjuXkaAouZrd6mIE6yYC",
                json={"status": "ok"},
                status=200,
            )

            client = CADClient(config_path=str(config_path))
            result = client.get("https://api.nasa.gov/planetary/apod?api_key=Y8J2mcPKdhjVjUSSYdSGkjuXkaAouZrd6mIE6yYC")

            print(result.data)
            print(result.cad_summary)
            print(result.decision)
            print(result.confidence)

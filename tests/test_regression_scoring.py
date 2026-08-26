import json
from pathlib import Path
import responses
from apiris import ApirisClient
from apiris.config import ApirisConfig


def test_clean_traffic_corpus_regression(tmp_path: Path):
    corpus_path = Path(__file__).resolve().parents[1] / "data" / "clean_traffic_corpus.json"
    assert corpus_path.exists(), f"Corpus not found at {corpus_path}"

    with open(corpus_path, "r", encoding="utf-8") as f:
        corpus = json.load(f)

    clean_samples = corpus.get("clean_samples", [])
    assert len(clean_samples) >= 10, "Expected at least 10 clean samples in corpus"

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        json.dumps(
            {
                "apiris": {
                    "enable_ai": False,
                    "integrity_threshold": 0.40,
                    "availability_threshold": 0.40,
                    "anomaly_threshold": 0.70,
                    "mode": "enforce",
                    "log_dir": str(tmp_path / "logs"),
                }
            }
        )
    )

    client = ApirisClient(config_path=str(config_path))

    with responses.RequestsMock() as mock:
        for sample in clean_samples:
            url = sample["url"]
            method = getattr(responses, sample["method"].upper())
            mock.add(
                method,
                url,
                body=sample["body"],
                status=sample["status"],
                headers=sample["headers"],
            )

            res = client.request(sample["method"], url)
            assert res.status_code == 200
            assert res.decision.action == "pass_through", (
                f"Sample {sample['id']} failed with action {res.decision.action}, "
                f"tradeoff={res.decision.tradeoff}, cad_scores={res.cad_summary.cad_scores}"
            )
            assert res.cad_summary.cad_scores["C_score"] >= 0.40
            assert res.cad_summary.cad_scores["A_score"] >= 0.40
            assert res.cad_summary.cad_scores["D_score"] >= 0.40
            assert res.confidence >= 0.50

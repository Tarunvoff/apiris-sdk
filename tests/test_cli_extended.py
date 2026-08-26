"""
Comprehensive Tests for Extended Apiris CLI Subcommands (v1.1.0)
"""

import json
from pathlib import Path
from typer.testing import CliRunner
import responses

from apiris.cli import app

runner = CliRunner()


def test_cli_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.1.0" in result.output
    assert "Deterministic AI Reliability" in result.output


def test_cli_status_command():
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Model Storage Status" in result.output
    assert "CVE Advisory System" in result.output


def test_cli_check_command(tmp_path: Path):
    with responses.RequestsMock() as mock:
        mock.add(responses.GET, "https://api.test.org/v1/health", json={"status": "healthy"}, status=200)
        result = runner.invoke(app, ["check", "https://api.test.org/v1/health"])
        assert result.exit_code == 0
        assert "Apiris Reliability Analysis" in result.output
        assert "Decision Verdict" in result.output
        assert "pass_through" in result.output


def test_cli_cve_commands():
    # Test single vendor
    res_ghost = runner.invoke(app, ["cve", "ghost"])
    assert res_ghost.exit_code == 0
    assert "CVE Security Advisory: GHOST" in res_ghost.output
    assert "CVE-2026-26980" in res_ghost.output

    # Test list vendors
    res_list = runner.invoke(app, ["cve", "--list-vendors"])
    assert res_list.exit_code == 0
    assert "Tracked CVE Vendors" in res_list.output
    assert "ghost" in res_list.output
    assert "fastapi" in res_list.output


def test_cli_benchmark_command():
    repo_root = Path(__file__).resolve().parents[1]
    corpus_path = str(repo_root / "data" / "clean_traffic_corpus.json")
    result = runner.invoke(app, ["benchmark", "--corpus", corpus_path])
    assert result.exit_code == 0
    assert "Benchmark Category Performance" in result.output
    assert "Clean" in result.output
    assert "Action Distribution" in result.output
    assert "Scoring Pipeline Overhead" in result.output


def test_cli_calibrate_command(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    corpus_path = str(repo_root / "data" / "clean_traffic_corpus.json")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("apiris:\n  mode: enforce\n", encoding="utf-8")

    # Run without --apply
    result = runner.invoke(app, ["calibrate", "--corpus", corpus_path, "--config", str(cfg_file)])
    assert result.exit_code == 0
    assert "Threshold Calibration Diff" in result.output
    assert "integrity_threshold" in result.output

    # Run with --apply
    res_apply = runner.invoke(app, ["calibrate", "--corpus", corpus_path, "--config", str(cfg_file), "--apply"])
    assert res_apply.exit_code == 0
    assert "Successfully applied derived thresholds" in res_apply.output
    content = cfg_file.read_text(encoding="utf-8")
    assert "integrity_threshold" in content


def test_cli_models_list_command():
    result = runner.invoke(app, ["models", "list"])
    assert result.exit_code == 0
    assert "Per-API Anomaly Baselines" in result.output
    assert "_global" in result.output
    assert "Global Placeholder" in result.output
    assert "Trained Baseline" in result.output


def test_cli_models_train_command(tmp_path: Path):
    samples_file = tmp_path / "samples.json"
    sample_data = [
        {"city": "CityA", "temperature": 21.5, "humidity": 50},
        {"city": "CityB", "temperature": 22.0, "humidity": 55},
        {"city": "CityC", "temperature": 19.5, "humidity": 60},
        {"city": "CityD", "temperature": 25.0, "humidity": 45},
        {"city": "CityE", "temperature": 23.1, "humidity": 52},
    ]
    samples_file.write_text(json.dumps(sample_data), encoding="utf-8")

    result = runner.invoke(app, ["models", "train", "api.custom-weather.org", "--samples", str(samples_file)])
    assert result.exit_code == 0
    assert "Successfully trained per-API baseline" in result.output
    assert "api.custom-weather.org" in result.output


def test_cli_drift_command(tmp_path: Path):
    result = runner.invoke(app, ["drift", "api.payments.net"])
    assert result.exit_code == 0
    assert "Drift Analysis: api.payments.net" in result.output


def test_cli_doctor_command():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "System Diagnostic & Integrity Audit" in result.output
    assert "Configuration Schema" in result.output
    assert "Model Assets" in result.output
    assert "CVE Dataset Integrity" in result.output
    assert "All diagnostic checks passed" in result.output


def test_cli_report_command(tmp_path: Path):
    repo_root = Path(__file__).resolve().parents[1]
    corpus_path = str(repo_root / "data" / "clean_traffic_corpus.json")
    out_file = tmp_path / "calibration_report.md"

    result = runner.invoke(app, ["report", "--corpus", corpus_path, "--output", str(out_file)])
    assert result.exit_code == 0
    assert "Calibration report written to" in result.output
    assert out_file.exists()
    report_text = out_file.read_text(encoding="utf-8")
    assert "# Apiris Calibration & Performance Report" in report_text
    assert "Clean Traffic" in report_text

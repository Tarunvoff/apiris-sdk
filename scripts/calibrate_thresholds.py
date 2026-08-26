"""
Apiris CAD Threshold Calibration and Verification Script

Executes the synthetic corpus across legacy (v1.0.2) vs recalibrated (v1.1.0)
scoring logic and computes score distributions, false positive rates, and generates
the official calibration report in docs/CALIBRATION_REPORT.md.
"""

from __future__ import annotations

from pathlib import Path

from apiris.benchmark import run_corpus_benchmark
from apiris.calibration import generate_calibration_report
from apiris.config import ApirisConfig


def run_benchmark():
    repo_root = Path(__file__).resolve().parents[1]
    corpus_path = repo_root / "data" / "clean_traffic_corpus.json"
    assert corpus_path.exists(), f"Corpus missing: {corpus_path}"

    v110_cfg = ApirisConfig(
        strict_zero_tolerance=False,
        integrity_threshold=0.40,
        availability_threshold=0.40,
        anomaly_threshold=0.70,
        hysteresis_band=0.05,
        enable_ai=False,
    )

    benchmark_res = run_corpus_benchmark(corpus_path=corpus_path, config=v110_cfg)

    clean_info = benchmark_res["categories"].get("clean", {})
    deg_info = benchmark_res["categories"].get("degraded", {})
    adv_info = benchmark_res["categories"].get("adversarial", {})

    print(f"=== Apiris Calibration Results ===")
    print(f"Clean Traffic Samples: {clean_info.get('total')}")
    print(f"  - v1.1.0 Pass Through Rate: {clean_info.get('pass_through')}/{clean_info.get('total')} ({clean_info.get('pass_through_rate', 0.0):.1%})")
    print(f"  - v1.1.0 Average Confidence (Clean): {clean_info.get('mean_confidence')}")
    print(f"Degraded Traffic Protection Rate: {deg_info.get('total') - deg_info.get('pass_through')}/{deg_info.get('total')} ({1.0 - deg_info.get('pass_through_rate', 0.0):.1%})")
    print(f"Adversarial Traffic Protection Rate: {adv_info.get('total') - adv_info.get('pass_through')}/{adv_info.get('total')} ({1.0 - adv_info.get('pass_through_rate', 0.0):.1%})")

    report_content = generate_calibration_report(benchmark_res, fmt="md")
    report_path = repo_root / "docs" / "CALIBRATION_REPORT.md"
    report_path.write_text(report_content, encoding="utf-8")
    print(f"Calibration report generated: {report_path}")


if __name__ == "__main__":
    run_benchmark()

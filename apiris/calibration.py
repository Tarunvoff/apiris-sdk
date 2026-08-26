"""
Apiris CAD Threshold Calibration and Report Generation Engine
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from apiris.benchmark import run_corpus_benchmark
from apiris.config import ApirisConfig, load_config


def derive_thresholds_from_corpus(
    corpus_path: Optional[Path | str] = None,
    current_config: Optional[ApirisConfig] = None,
) -> Dict[str, Any]:
    if corpus_path is None:
        repo_root = Path(__file__).resolve().parents[1]
        corpus_path = repo_root / "data" / "clean_traffic_corpus.json"
    else:
        corpus_path = Path(corpus_path)

    if current_config is None:
        current_config = ApirisConfig()

    # Run benchmark across zero-tolerance vs calibrated configuration
    benchmark_res = run_corpus_benchmark(corpus_path=corpus_path, config=current_config)

    clean_samples = benchmark_res["categories"]["clean"]["samples"]
    
    # Calculate distributions for clean samples
    c_scores = [s["cad_scores"]["C_score"] for s in clean_samples]
    a_scores = [s["cad_scores"]["A_score"] for s in clean_samples]
    d_scores = [s["cad_scores"]["D_score"] for s in clean_samples]

    min_c = min(c_scores) if c_scores else 1.0
    min_a = min(a_scores) if a_scores else 1.0
    min_d = min(d_scores) if d_scores else 1.0

    # Derive safe health thresholds below minimal clean scores (0.40 baseline)
    derived_c = 0.40 if min_c >= 0.80 else round(max(0.20, min_c - 0.10), 2)
    derived_a = 0.40 if min_a >= 0.80 else round(max(0.20, min_a - 0.10), 2)
    derived_d = 0.40 if min_d >= 0.80 else round(max(0.20, min_d - 0.10), 2)

    diff = [
        {
            "parameter": "integrity_threshold",
            "current": current_config.integrity_threshold,
            "derived": derived_d,
            "status": "CALIBRATED" if abs(current_config.integrity_threshold - derived_d) < 0.05 else "DRIFT",
        },
        {
            "parameter": "availability_threshold",
            "current": current_config.availability_threshold,
            "derived": derived_a,
            "status": "CALIBRATED" if abs(current_config.availability_threshold - derived_a) < 0.05 else "DRIFT",
        },
        {
            "parameter": "anomaly_threshold",
            "current": current_config.anomaly_threshold,
            "derived": 0.70,
            "status": "CALIBRATED" if abs(current_config.anomaly_threshold - 0.70) < 0.05 else "DRIFT",
        },
        {
            "parameter": "hysteresis_band",
            "current": current_config.hysteresis_band,
            "derived": 0.05,
            "status": "CALIBRATED" if abs(current_config.hysteresis_band - 0.05) < 0.01 else "DRIFT",
        },
    ]

    return {
        "benchmark": benchmark_res,
        "current_config": current_config,
        "derived_thresholds": {
            "integrity_threshold": derived_d,
            "availability_threshold": derived_a,
            "anomaly_threshold": 0.70,
            "hysteresis_band": 0.05,
        },
        "diff": diff,
    }


def apply_thresholds_to_config(config_path: Path | str, new_thresholds: Dict[str, Any]) -> None:
    path = Path(config_path)
    data: Dict[str, Any] = {}
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            data = {}

    apiris_sec = data.setdefault("apiris", {})
    for k, v in new_thresholds.items():
        apiris_sec[k] = v

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def generate_calibration_report(benchmark_res: Dict[str, Any], fmt: str = "md") -> str:
    clean_info = benchmark_res["categories"].get("clean", {})
    deg_info = benchmark_res["categories"].get("degraded", {})
    adv_info = benchmark_res["categories"].get("adversarial", {})
    lat = benchmark_res.get("pipeline_latency", {})
    act_dist = benchmark_res.get("action_distribution", {})

    if fmt.lower() == "html":
        return f"""<!DOCTYPE html>
<html>
<head><title>Apiris Calibration Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
th, td {{ border: 1px solid #334155; padding: 12px; text-align: left; }}
th {{ background: #1e293b; color: #38bdf8; }}
.badge-clean {{ color: #4ade80; font-weight: bold; }}
.badge-alert {{ color: #f87171; font-weight: bold; }}
</style>
</head>
<body>
<h1>Apiris Calibration & Performance Report</h1>
<p>Generated for corpus version {benchmark_res.get('corpus_version')}</p>
<h2>Summary Metrics</h2>
<table>
<tr><th>Category</th><th>Total Samples</th><th>Pass Through Rate</th><th>Mean Confidence</th></tr>
<tr><td>Clean Traffic</td><td>{clean_info.get('total')}</td><td class="badge-clean">{clean_info.get('pass_through_rate', 0.0):.1%}</td><td>{clean_info.get('mean_confidence')}</td></tr>
<tr><td>Degraded Traffic</td><td>{deg_info.get('total')}</td><td>{deg_info.get('pass_through_rate', 0.0):.1%}</td><td>{deg_info.get('mean_confidence')}</td></tr>
<tr><td>Adversarial Traffic</td><td>{adv_info.get('total')}</td><td class="badge-alert">{adv_info.get('pass_through_rate', 0.0):.1%}</td><td>{adv_info.get('mean_confidence')}</td></tr>
</table>
<h2>Scoring Pipeline Latency</h2>
<p>p50: {lat.get('p50')}ms | p95: {lat.get('p95')}ms | p99: {lat.get('p99')}ms (Mean: {lat.get('mean')}ms)</p>
</body></html>"""

    # Markdown format
    lines = [
        f"# Apiris Calibration & Performance Report",
        "",
        f"- **Corpus Version**: `{benchmark_res.get('corpus_version')}`",
        f"- **Total Evaluated**: `{benchmark_res.get('total_samples')}` samples",
        f"- **Clean Pass-Through**: **`{clean_info.get('pass_through_rate', 0.0):.1%}`**",
        "",
        "## 1. Category Breakdown",
        "",
        "| Category | Samples | Pass-Through Rate | Mean Confidence | Pipeline Latency (p50 / p95) |",
        "|----------|---------|-------------------|-----------------|-------------------------------|",
        f"| **Clean Traffic** | {clean_info.get('total')} | **{clean_info.get('pass_through_rate', 0.0):.1%}** | {clean_info.get('mean_confidence')} | {clean_info.get('latency', {}).get('p50')}ms / {clean_info.get('latency', {}).get('p95')}ms |",
        f"| **Degraded Traffic** | {deg_info.get('total')} | {deg_info.get('pass_through_rate', 0.0):.1%} | {deg_info.get('mean_confidence')} | {deg_info.get('latency', {}).get('p50')}ms / {deg_info.get('latency', {}).get('p95')}ms |",
        f"| **Adversarial Traffic** | {adv_info.get('total')} | {adv_info.get('pass_through_rate', 0.0):.1%} | {adv_info.get('mean_confidence')} | {adv_info.get('latency', {}).get('p50')}ms / {adv_info.get('latency', {}).get('p95')}ms |",
        "",
        "## 2. Action Distribution",
        "",
        "| Action | Frequency | Percentage |",
        "|--------|-----------|------------|",
    ]
    tot = benchmark_res.get("total_samples", 1)
    for act, cnt in sorted(act_dist.items(), key=lambda x: -x[1]):
        lines.append(f"| `{act}` | {cnt} | {cnt/tot:.1%} |")

    lines.extend([
        "",
        "## 3. Pipeline Latency Breakdown",
        "",
        f"- **p50**: `{lat.get('p50')} ms`",
        f"- **p95**: `{lat.get('p95')} ms`",
        f"- **p99**: `{lat.get('p99')} ms`",
        f"- **Mean**: `{lat.get('mean')} ms`",
        "",
    ])
    return "\n".join(lines)

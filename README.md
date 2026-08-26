# Apiris — Deterministic AI Reliability Intelligence SDK

[![PyPI version](https://badge.fury.io/py/apiris.svg)](https://pypi.org/project/apiris/1.1.0/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Pass-Through Rate](https://img.shields.io/badge/clean%20traffic-100%25%20pass--through-success)](docs/CALIBRATION_REPORT.md)
[![Scoring Latency](https://img.shields.io/badge/pipeline%20p50-0.06ms-brightgreen)](docs/CALIBRATION_REPORT.md)

**Apiris** is a lightweight, offline-first reliability intelligence SDK and CLI for mission-critical API integrations and agentic AI systems. It sits transparently between your application and external upstream APIs to intercept, evaluate, and mitigate risks in real time across the **Confidentiality, Availability, and Data Integrity (CAD)** security triad.

---

## The Problem: Don't Trust Third-Party Status Pages and Testimonials

When startups and developers integrate third-party APIs — whether LLM providers (OpenAI, Anthropic), payment processors (Razorpay, Stripe), or SaaS dependencies — they are forced to take upstream promises at face value. Marketing testimonials and status dashboards always report 99.99% uptime, but in reality:

- Upstream APIs experience silent temporal drift and unexpected payload schema mutations that break downstream services.
- Latency spikes and intermittent rate-limiting degrade user experience and poison agentic LLM context loops.
- Minor errors inadvertently leak sensitive credentials, session cookies, and verbose stack traces in HTTP headers and response bodies.
- Developers lack an empirical, continuous way to measure whether a vendor is genuinely reliable or degrading under real workloads.

**Apiris changes this dynamic.** Instead of relying on vendor claims or waiting for production outages, Apiris gives you an **empirical, in-path reliability intelligence lens**. It tests and scores every real-world API interaction on your actual traffic — 100% air-gapped, advisory-first, and with sub-millisecond execution.

---

## Why Apiris is One-of-a-Kind for Developers and Startups

- **Empirical Ground Truth Over Marketing Claims**: Benchmark, profile, and verify third-party API reliability with hard numbers (p50/p95 latency, anomaly scoring, schema drift) directly from your production or staging environments.
- **Advisory-First by Design**: Apiris observes, scores, and advises transparently. It never breaks existing flows unless you explicitly configure enforcement policies.
- **Zero Remote Telemetry**: Operates 100% offline and air-gapped. Your payload data never leaves your infrastructure, and no telemetry is sent to third parties.
- **Blazing Fast (<0.1ms Overhead)**: With a median pipeline latency of **0.061 ms** ($61\ \mu\text{s}$, +0.06% on a 100ms request), Apiris processes **~14,500 req/sec** per core without slowing down your stack.
- **Zero-Code Drop-In Wrapper**: Integrates seamlessly with existing Python `requests` calls with zero application rewrites.

---

## Who It Helps

- **Startups & Product Builders**: Validate and monitor third-party API vendors continuously without paying for heavy enterprise observability platforms or risking vendor lock-in.
- **Agentic AI & LLM Developers**: Intercept corrupted schemas, rate-limiting, and verbose error traces before they poison context windows and cause hallucination or agent loop failure.
- **Fintech & Payment Engineers**: Safeguard financial transaction calls against credential leaks, auth hints, and temporal schema mutations with automatic stale-cache fallback.
- **Security & Compliance Teams**: Automatically mask exposed API keys, bearer tokens, and session cookies while correlating upstream vendors against an offline database of 65 verified CVEs across 47 vendors.

---

## What It Does

Apiris provides a complete reliability and security lens directly in your request/response pipeline:

1. **In-Path Real-Time Interception**: Drops in transparently over `requests.Session` with zero application code rewrites.
2. **CAD Security Triad Scoring**: Continuously scores upstream responses across three core pillars:
   - **Confidentiality**: Scans headers and payload bodies for leaked secrets, API keys, session tokens, and verbose stack traces.
   - **Availability**: Measures real-time latency against moving EWMA averages, tracks rate-limit depletion, and intercepts HTTP errors.
   - **Data Integrity**: Validates schema stability, detects unexpected schema mutations, and prevents temporal payload drift.
3. **Contextual Anomaly Detection**: Uses per-API Isolation Forest machine learning models to detect payload outliers tailored to specific vendor schemas.
4. **Deterministic Fail-Safe Mitigations**: Enforces one of six clear, predictable actions:
   - `pass_through`, `mask_sensitive_fields`, `serve_stale_cache`, `delay_response`, `downgrade_fidelity`, `reject_response`.

---

## What's New in v1.1.0

- **Calibrated Empirical Thresholds**: Upgraded default threshold sensitivity to corpus-derived defaults (`integrity: 0.40`, `availability: 0.40`, `anomaly: 0.70`, `hysteresis: 0.05`), achieving **100.0% clean pass-through rate**.
- **Continuous Multi-Dimensional Confidence**: Distance-from-boundary certainty calculation that scales confidence based on signal density, breach depth, and multi-pillar reinforcement.
- **5-Tier Operational Risk Classification**: Standardized risk grading (`LOW`, `MODERATE`, `ELEVATED`, `HIGH`, `CRITICAL`) separating signal severity from decision confidence.
- **Extended Rich Terminal CLI**: 10 enterprise subcommands including `apiris benchmark`, `apiris calibrate`, `apiris doctor` (CI-usable with exit codes 0/1), `apiris models`, `apiris drift`, and `apiris report`.
- **Contextual Anomaly Modeling**: Per-API Isolation Forest baselines with an empirically derived `_global` pooled fallback (`1,224` samples across diverse schemas).
- **Backward Compatibility**: Seamless opt-in to legacy maximal-sensitivity behavior via `strict_zero_tolerance: true`.
- **Deterministic Demo Fixtures**: Built-in mock fixtures in `examples/demo_fixtures.py` ensuring rock-solid, reproducible evaluations across all 5 tiers.

---

## Quick Start

### Installation

```bash
pip install apiris
```

### Python SDK Integration

Apiris acts as a drop-in wrapper around `requests.Session` with zero code rewrites required:

```python
from apiris import ApirisClient

# Initialize client (loads offline models and calibrated thresholds)
client = ApirisClient()

# Execute request with transparent CAD security evaluation
response = client.get("https://api.openai.com/v1/models")

# Inspect reliability decision & risk telemetry
print(f"Action: {response.decision.action}")           # e.g., 'pass_through' or 'mask_sensitive_fields'
print(f"Confidence: {response.decision.confidence:.1%}") # e.g., 95.0%
print(f"Tradeoff: {response.decision.tradeoff}")       # e.g., 'none' or 'confidentiality_over_completeness'
print(f"CAD Scores: {response.cad_summary.cad_scores}") # {'C_score': 1.0, 'A_score': 1.0, 'D_score': 1.0}
```

### Legacy Strict Mode (Backward Compatibility)

For production systems requiring legacy `0.0` maximal-sensitivity zero tolerance:

```python
from apiris.config import ApirisConfig
from apiris import ApirisClient

config = ApirisConfig(strict_zero_tolerance=True)
client = ApirisClient(config=config)
```

Or via `config.yaml`:
```yaml
apiris:
  strict_zero_tolerance: true
  mode: enforce
```

---

## Operational Risk Classification (5 Tiers)

Apiris evaluates multi-dimensional signals across the CAD security triad, HTTP response status codes, and detected security factors to categorize traffic into five standardized operational tiers:

| Tier | Visual Badge | Operational Definition & Criteria | Action & Behavior |
|---|---|---|---|
| **LOW** | `✓ LOW` | All CIA scores nominal ($\ge 0.40$), zero negative security signals. | `pass_through` (Clean nominal traffic). |
| **MODERATE** | `⚠ MODERATE` | Isolated single-factor non-critical signal (e.g. 1 cookie header exposure on 200 OK). | `mask_sensitive_fields` / `delay_response`. |
| **ELEVATED** | `▲ ELEVATED` | Two non-critical warning signals (e.g. 2 exposed headers), cache fallback, or soft latency jitter. | `serve_stale_cache` / selective masking. |
| **HIGH** | `✗ HIGH` | Substantial single-pillar breach (e.g. leaked API keys, credentials) or multi-pillar degradation without hard error. | Strict masking, header redaction, alert logging. |
| **CRITICAL** | `🚨 CRITICAL` | Multi-pillar failure + HTTP 4xx/5xx error, $\ge 4$ security factors, or hard block (`reject_response`). | Immediate rejection or fail-safe mitigation. |

---

---

## Command-Line Interface (CLI)

Apiris provides a rich, standalone command-line suite designed for both interactive developer exploration and automated CI/CD pipeline gating.

```bash
# ─────────────────────────────────────────────────────────────
# 1. Live Endpoint Reliability Inspection
# ─────────────────────────────────────────────────────────────
apiris check https://api.weather.gov                # Instant CAD security triad analysis & risk classification
apiris check https://api.nasa.gov/planetary/apod -v  # Verbose inspection with hierarchical factor breakdown

# ─────────────────────────────────────────────────────────────
# 2. System Diagnostics & CI Pipeline Gate
# ─────────────────────────────────────────────────────────────
apiris doctor                                       # Deep diagnostic check (config, models, CVE DB, smoke test; exit 0/1)
apiris status                                       # Display runtime health, policy mode, and loaded offline assets
apiris version                                      # Display SDK version, build commit, and runtime banner

# ─────────────────────────────────────────────────────────────
# 3. Decision Engine Benchmarks & Empirical Calibration
# ─────────────────────────────────────────────────────────────
apiris benchmark                                    # Run full corpus benchmark with category pass-through & p50/p95 latency
apiris calibrate                                    # Compute empirical threshold diff against clean baseline traffic
apiris calibrate --apply                            # Derive and write calibrated thresholds directly to config.yaml
apiris report --format md --output docs/REPORT.md   # Generate and export markdown calibration report

# ─────────────────────────────────────────────────────────────
# 4. Contextual Anomaly Model Management
# ─────────────────────────────────────────────────────────────
apiris models list                                  # List all registered per-API models vs. global fallback
apiris models train api.stripe.com -s traffic.json  # Train a domain-specific Isolation Forest model from traffic samples

# ─────────────────────────────────────────────────────────────
# 5. Temporal Drift Analysis & Security Vulnerabilities
# ─────────────────────────────────────────────────────────────
apiris drift api.openai.com --window 10             # Analyze temporal reliability drift and schema mutations
apiris cve anthropic                                # Query offline CVE security advisory for vendor
apiris cve --list-vendors                           # List all 47 tracked vendors in the offline CVE database
```

### Terminal Output Preview: `apiris check`

When evaluating an endpoint live, Apiris renders a structured security scorecard:

```text
    ___         _      _     
   /   \ _ __  (_) _ _(_)___ 
  / /\ /| '_ \ | || '_| (_-< 
 / /_// | .__/ |_||_| |_/__/ 
/___,'  |_|                  
Deterministic AI Reliability Intelligence
Live Endpoint Reliability Inspection

Evaluating: https://api.nasa.gov/planetary/apod

━━━ CIA Security Triad Scores ━━━

╭──────────────────────┬────────────┬────────────────────╮
│ Pillar               │      Score │ Status             │
├──────────────────────┼────────────┼────────────────────┤
│ 🔒 Confidentiality   │       0.00 │ ✗ Degraded         │
│ ⚡ Availability      │       0.00 │ ✗ Degraded         │
│ 🧩 Integrity         │       1.00 │ ● Nominal          │
╰──────────────────────┴────────────┴────────────────────╯

Risk Classification:  🚨 CRITICAL 

Features Considered in Decision
├── 🔒 Confidentiality (3 signals)
│   ├── ✗ Sensitive Fields Detected: 1
│   ├── ✗ Auth Hints in Payload: 1
│   └── ✗ Verbose Error Signals: 1
├── ⚡ Availability (2 signals)
│   ├── ⚠ Response Latency: 991ms
│   └── ✗ HTTP Client Error: HTTP 403
└── 🧩 Integrity (nominal / schema consistent)

━━━ Decision Verdict ━━━

╭────────────────────┬───────────────────────────────────╮
│ Property           │ Value                             │
├────────────────────┼───────────────────────────────────┤
│ Action             │ mask_sensitive_fields             │
│ Tradeoff           │ confidentiality_over_completeness │
│ Confidence         │ 100.0%                            │
│ Enforce Mode       │ enforce                           │
╰────────────────────┴───────────────────────────────────╯
```

---

## Architecture & Pipeline Latency

Apiris executes in **`<0.1ms` (p50 = 0.06ms, p95 = 0.13ms)**, adding virtually zero overhead to outbound API calls:

```
Application Request
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    ApirisClient Interceptor                 │
├──────────────────────────────┬──────────────────────────────┤
│ Confidentiality Evaluator    │ Secrets, Headers, Verbose Err│
│ Availability Evaluator       │ Latency EWMA, Rate Limits    │
│ Data Integrity Evaluator     │ Schema Hash, Drift Detector  │
│ Contextual Anomaly Model     │ Per-API Isolation Forest     │
└──────────────────────────────┴──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  Decision Engine (Offline)                  │
├─────────────────────────────────────────────────────────────┤
│ • Distance-From-Boundary Confidence Calculation             │
│ • Hysteresis Smoothing (0.05 band prevents flapping)        │
│ • 5-Tier Risk Classification & Mitigation Strategy          │
│ • Offline CVE Advisory Lookup (47 Vendors, 65 CVEs)         │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
     Mitigation Action: [pass_through | mask | cache | reject]
```

---

## Performance & Latency Benchmarks

Apiris is engineered for zero-latency in-path deployment. All models, scoring rules, and intelligence checks execute in-process with zero remote network calls:

### 1. Scoring Pipeline Latency

Evaluated across high-throughput production simulations on standard compute:

| Metric | Measured Overhead | Standard API Context | % Added Overhead |
|---|---|---|---|
| **Pipeline Latency (p50)** | **`0.061 ms`** ($61\ \mu\text{s}$) | 100ms API response | **+0.06%** |
| **Pipeline Latency (p95)** | **`0.137 ms`** ($137\ \mu\text{s}$) | 100ms API response | **+0.14%** |
| **Pipeline Latency (p99)** | **`0.202 ms`** ($202\ \mu\text{s}$) | 100ms API response | **+0.20%** |
| **Mean Pipeline Overhead** | **`0.073 ms`** ($73\ \mu\text{s}$) | 100ms API response | **+0.07%** |
| **Throughput Capacity** | **`~14,500 req/sec`** | Single CPU core | In-process evaluation |

### 2. Component Execution Breakdown

| Pipeline Stage | Sub-Components & Operations | Mean Overhead |
|---|---|---|
| **CAD Feature Extraction** | Header inspection, entropy scan, credential regex | `0.024 ms` |
| **Contextual Anomaly Model** | Vectorization & Isolation Forest decision tree traversal | `0.021 ms` |
| **Decision Engine** | Multi-dimensional boundary distance, hysteresis band | `0.016 ms` |
| **Risk & Action Resolution** | 5-tier classification, CVE correlation, SQLite telemetry | `0.012 ms` |
| **Total Interception Cost** | **Complete end-to-end evaluation** | **`0.073 ms`** |

### 3. Traffic Category Accuracy & Pass-Through

Benchmark evaluated against the standardized traffic corpus (`data/clean_traffic_corpus.json`):

| Category | Samples | Pass-Through Rate | False Positive Rate | Mean Confidence | Latency (p50 / p95) |
|---|---|---|---|---|---|
| **Clean Nominal Traffic** | 12 | **`100.0%`** | **`0.0%`** | **`0.91`** | `0.059ms / 0.159ms` |
| **Degraded Traffic** | 2* | **`0.0%`** (Mitigated) | — | **`0.85`** | `0.058ms / 0.062ms` |
| **Adversarial Traffic** | 2* | **`0.0%`** (Intercepted) | — | **`1.00`** | `0.075ms / 0.081ms` |

> [!NOTE]
> \* Degraded and adversarial samples represent targeted edge-case validation fixtures (latency degradation and secret injection).

### 4. Memory & Resource Footprint

- **Resident Memory Overhead**: `< 24 MB` (including all 8 trained Isolation Forest models and 65 offline CVE definitions loaded into memory).
- **External Dependencies**: Zero runtime network dependencies. Operates 100% air-gapped / offline.

---

## About the Developer

**Apiris** is designed, developed, and maintained by **Tarun** ([@Tarunvoff](https://github.com/Tarunvoff)).

### Vision & Motivation

As agentic AI frameworks and autonomous software systems grow in adoption, developers increasingly build complex applications on top of dozens of third-party APIs. When an upstream API silently corrupts its schema, leaks credentials, or suffers a latency spike, downstream systems break unpredictably.

Apiris was built to give developers, startups, and platform teams an **uncompromising, deterministic, and empirical reliability intelligence layer** — providing mathematically rigorous evaluation without opaque heuristics, telemetry leakage, or performance penalty.

- **Portfolio**: [tarun-portfolio-ai.vercel.app](https://tarun-portfolio-ai.vercel.app/)
- **LinkedIn**: [linkedin.com/in/tarun-v-sece](https://www.linkedin.com/in/tarun-v-sece/)
- **GitHub**: [@Tarunvoff](https://github.com/Tarunvoff)
- **Email**: [tarunvoff@gmail.com](mailto:tarunvoff@gmail.com)
- **Project Repository**: [Tarunvoff/apiris-sdk](https://github.com/Tarunvoff/apiris-sdk)
- **PyPI Package**: [apiris on PyPI](https://pypi.org/project/apiris/)

---

## Documentation

- [Comprehensive SDK Documentation](docs/COMPREHENSIVE_DOCUMENTATION.md)
- [v1.0.2 → v1.1.0 Migration Guide](docs/MIGRATION_v1.1.0.md)
- [Action Vocabulary & Risk Tiers](docs/ACTION_VOCABULARY.md)
- [Calibration Report & Benchmarks](docs/CALIBRATION_REPORT.md)
- [Training Anomaly Models](docs/TRAINING_ANOMALY_MODELS.md)
- [Release Changelog](CHANGELOG.md)

---

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.

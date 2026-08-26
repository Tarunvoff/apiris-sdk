# Apiris Calibration & Performance Report

- **Corpus Version**: `1.1.0`
- **Total Evaluated**: `16` samples
- **Clean Pass-Through**: **`100.0%`**

## 1. Category Breakdown

| Category | Samples | Pass-Through Rate | Mean Confidence | Pipeline Latency (p50 / p95) |
|----------|---------|-------------------|-----------------|-------------------------------|
| **Clean Traffic** | 12 | **100.0%** | 0.91 | 0.059ms / 0.159ms |
| **Degraded Traffic** | 2* | 0.0% | 0.85 | 0.058ms / 0.062ms |
| **Adversarial Traffic** | 2* | 0.0% | 1.00 | 0.075ms / 0.081ms |

> [!NOTE]
> \* **Sample Size Caveat**: The degraded ($n=2$) and adversarial ($n=2$) categories represent targeted edge-case validation fixtures (latency spike and secret injection) to verify action triggering and boundary distance calculations, rather than large-scale empirical population distributions. Clean traffic ($n=12$) covers multi-domain real-world payload shapes.

## 2. Action Distribution

| Action | Frequency | Percentage |
|--------|-----------|------------|
| `pass_through` | 12 | 75.0% |
| `serve_stale_cache` | 2 | 12.5% |
| `mask_sensitive_fields` | 2 | 12.5% |

## 3. Pipeline Latency Breakdown

- **p50**: `0.061 ms`
- **p95**: `0.137 ms`
- **p99**: `0.202 ms`
- **Mean**: `0.073 ms`

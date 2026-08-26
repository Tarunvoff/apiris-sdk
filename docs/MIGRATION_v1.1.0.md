# Migration Guide: Apiris v1.0.2 → v1.1.0

This guide outlines changes in `v1.1.0` and steps required for existing production installations.

---

## 1. Summary of Changes

| Area | v1.0.2 Behavior | v1.1.0 Behavior | Action Required |
|------|-----------------|-----------------|-----------------|
| **Default Thresholds** | `0.0` (Maximal sensitivity) | `0.40` (Calibrated sane defaults) | None for new users; opt in to legacy if desired |
| **Strict Zero Tolerance** | Implicit / default | `strict_zero_tolerance: true` flag | Add flag if relying on legacy 0.0 sensitivity |
| **Confidence Scoring** | Static / discontinuous | Continuous distance-from-boundary certainty | None (transparent improvement) |
| **Action Stability** | Hard step function (0.01 noise flap) | Hysteresis band (`0.05`) smoothing | None (prevents flapping) |
| **Anomaly Baselines** | Single global baseline | Contextual per-API baselines with `_global` fallback | None (automatic resolution) |
| **CVE Validation** | Manual database entries | Automated CI verification against NVD/GHSA | None |

---

## 2. Backward Compatibility for Existing Production Users

If your integration was explicitly tuned or intended to operate under legacy `0.0` maximal-sensitivity thresholds, you can preserve the exact legacy behavior by adding `strict_zero_tolerance: true` to your `config.yaml`:

```yaml
apiris:
  strict_zero_tolerance: true
  mode: enforce
```

Or programmatically in Python:
```python
from apiris.config import ApirisConfig
from apiris.client import ApirisClient

config = ApirisConfig(strict_zero_tolerance=True)
client = ApirisClient(config=config)
```

---

## 3. Upgrading to Calibrated Defaults (Recommended)

No code changes are required to benefit from calibrated scoring:
```bash
pip install --upgrade apiris
```

Clean API traffic will now reliably return:
- `action == "pass_through"`
- High confidence scores (`~0.90 – 1.00`)
- Low false-positive risk flagging

---

## 4. Anomaly Baseline Fallback Semantics

In `v1.1.0`, `AnomalyScorer` checks for domain-specific models (e.g. `api.weather.io`, `market.exchange.co`). For endpoints without a dedicated model, it falls back to `_global`.

> [!NOTE]
> The `_global` baseline is an empirical pooled aggregate across existing models (`sampleCount = 1,224`), configured with `coreFields: []` to avoid penalizing unfamiliar payload schemas. It is intended as **a conservative placeholder baseline for unseen APIs pending domain-specific training data**. For critical paths, follow [TRAINING_ANOMALY_MODELS.md](file:///c:/apiris-sdk/docs/TRAINING_ANOMALY_MODELS.md) to generate calibrated per-API models.

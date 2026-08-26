# Training and Adding Per-API Anomaly Baselines in Apiris SDK

## Overview

Apiris uses an offline Isolation Forest model to detect statistical and structural anomalies in API responses without requiring external network dependencies. 

Rather than relying purely on a single global baseline, `apiris v1.1.0+` supports **contextual per-API baselines** (`per-api_name` modeling), with a fallback to `_global` for unseen APIs.

---

## 1. Feature Representation

Every API response is extracted into a 12-dimensional feature vector:

| Index | Feature Name | Description | Normal Range |
|-------|--------------|-------------|--------------|
| 0 | `field_count` | Total number of JSON fields | 1 – 1,000 |
| 1 | `max_depth` | Maximum nesting depth | 1 – 8 |
| 2 | `array_count` | Number of JSON arrays in payload | 0 – 50 |
| 3 | `null_ratio` | Ratio of null values to total values | 0.0 – 0.2 |
| 4 | `numeric_mean` | Mean of numeric field values | Domain dependent |
| 5 | `numeric_std` | Standard deviation of numeric field values | Domain dependent |
| 6 | `numeric_min` | Minimum numeric value | Domain dependent |
| 7 | `numeric_max` | Maximum numeric value | Domain dependent |
| 8 | `numeric_jump` | Jump delta from previous response mean | 0.0 – Domain |
| 9 | `missing_core_ratio`| Proportion of expected schema paths missing | 0.0 |
| 10 | `repeat_count` | Consecutive identical payload repetitions | 0 – 5 |
| 11 | `time_since_identical` | Seconds since identical payload was seen | > 0 |

---

## 2. Model JSON Structure

Each entry in `apiris/models/anomaly_model.json` under `models` contains:

```json
{
  "api-identifier": {
    "sampleCount": 128,
    "coreFields": [
      "status",
      "data",
      "data.id",
      "data.amount"
    ],
    "mean": [12.4, 3.0, 1.0, 0.0, 45.2, 12.1, 0.0, 120.0, 0.0, 0.0, 0.0, -1.0],
    "std": [2.1, 0.5, 0.2, 0.02, 10.5, 4.2, 0.0, 25.0, 5.0, 0.01, 1.0, 5.0],
    "forest": {
      "sampleSize": 128,
      "trees": [
        {
          "feature": 0,
          "split": 1.2,
          "left": {"leaf": true, "size": 60},
          "right": {"leaf": true, "size": 68}
        }
      ]
    }
  }
}
```

---

## 3. How to Train a New Baseline

### Step 1: Collect Clean Traffic Samples
Collect 100–500 realistic, successful (HTTP 200) responses from your target API into a JSONL or JSON list.

### Step 2: Compute Feature Statistics
Extract feature vectors from the samples and compute empirical `mean` and `std` for normalization across the 12 features. Identify common `coreFields` (schema paths present in >= 95% of calls).

### Step 3: Train an Isolation Forest
Using `sklearn.ensemble.IsolationForest`:
```python
from sklearn.ensemble import IsolationForest
import numpy as np

# Standardize features: (X - mean) / std
X_standardized = (X - mean) / std

# Fit Isolation Forest
clf = IsolationForest(n_estimators=50, max_samples=128, random_state=42)
clf.fit(X_standardized)
```

### Step 4: Export to JSON Format
Export tree split nodes (`feature`, `split`, `left`, `right`, `leaf`, `size`) into standard Apiris JSON format.

### Step 5: Add to `anomaly_model.json`
Add your new model under key matching your API's host or route identifier:
```json
"models": {
  "api.stripe.com": { ... }
}
```

---

## 4. Fallback Behavior (`_global` Baseline)

If no explicit per-API model matches the request URL or host, `AnomalyScorer` automatically evaluates against the `_global` baseline.

### Derivation & Methodology (`scripts/train_global_anomaly_baseline.py`)
The `_global` baseline is generated via `scripts/train_global_anomaly_baseline.py` as an empirical pooled aggregate across existing per-API models:
- **Pooled Sample Count**: 1,224 requests across domains (weather, crypto markets, telemetry, seismic).
- **Core Fields**: Empty (`coreFields: []`), ensuring unfamiliar JSON schemas are not penalized purely for having different field names.
- **Pooled Mean & Standard Deviation**: Incorporates both intra-model and inter-model variance across all 12 feature dimensions.

> [!NOTE]
> The `_global` baseline serves as a **conservative placeholder baseline for unseen APIs pending domain-specific training data**. For critical production services with specialized payload shapes, training and checking in a per-API baseline (as described in Section 3) is strongly recommended.

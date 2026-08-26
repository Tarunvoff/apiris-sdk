# Apiris Decision Engine: Action Vocabulary & Operational Semantics

This document defines the exact operational vocabulary of the six decision engine actions emitted by Apiris SDK, their trigger conditions, and runtime interception behaviors.

---

## Action Hierarchy

Actions are graduated by protective severity from least restrictive (`pass_through`) to most restrictive (`reject_response`):

```
Level 0: pass_through
  ↓
Level 1: delay_response
  ↓
Level 2: serve_stale_cache  /  downgrade_fidelity
  ↓
Level 3: mask_sensitive_fields
  ↓
Level 4: reject_response
```

---

## Detailed Action Specifications

### 1. `pass_through`
- **Severity**: Level 0 (Normal)
- **Condition**: All CAD health scores exceed configured thresholds (`C_score >= T_C`, `A_score >= T_A`, `D_score >= T_D`).
- **Runtime Interception**: None. The raw upstream response is passed directly to the caller.
- **Trade-Off Emitted**: `"none"`

### 2. `delay_response`
- **Severity**: Level 1 (Traffic Smoothing)
- **Condition**: Availability score experiences minor latency jitter below `availability_delay_threshold`, but integrity remains solid.
- **Runtime Interception**: Injects a non-blocking pacing delay (`delay_ms`, default 400ms) to buffer bursty traffic or rate limits before returning the response.
- **Trade-Off Emitted**: `"integrity_over_availability"`

### 3. `serve_stale_cache`
- **Severity**: Level 2 (Resilience Fallback)
- **Condition**: Upstream service suffers availability degradation (`A_score < availability_threshold`), but previously cached healthy response exists within `cache_ttl_ms`.
- **Runtime Interception**: Returns the most recent cached payload with header annotations (`cacheAgeMs`), preventing upstream outage from cascading downstream.
- **Trade-Off Emitted**: `"availability_over_integrity"`

### 4. `downgrade_fidelity`
- **Severity**: Level 2 (Metadata Only)
- **Condition**: Simultaneous availability and integrity dip when policy prefer mode is `"integrity"`, or when cache is unavailable.
- **Runtime Interception**: Strips unverified response body and returns payload metadata (`bodyBytes`, `bodyHash`, headers) with status code.
- **Trade-Off Emitted**: `"integrity_over_availability"`

### 5. `mask_sensitive_fields`
- **Severity**: Level 3 (Privacy / Confidentiality Preservation)
- **Condition**: Confidentiality score falls below threshold (`C_score < confidentiality_threshold`) due to detected secrets, auth tokens, API keys, or verbose stack traces.
- **Runtime Interception**: Automatically redacts sensitive keys to `"[MASKED]"` recursively in JSON responses before returning to the caller.
- **Trade-Off Emitted**: `"confidentiality_over_completeness"`

### 6. `reject_response`
- **Severity**: Level 4 (Hard Integrity Block)
- **Condition**: Severe integrity corruption (`D_score < integrity_threshold`), unrecoverable schema tampering, or strict mode policy violation.
- **Runtime Interception**: Blocks response completely and raises/returns HTTP 503 with block reason `"integrity_risk"`.
- **Trade-Off Emitted**: `"integrity_over_availability"`

---

## Hysteresis & Action Stability

To prevent decision flapping on borderline noisy traffic (e.g. score oscillating between 0.39 and 0.41), Apiris applies a **hysteresis band** (`hysteresis_band = 0.05`):
- Entering an escalated action requires `score < threshold`.
- Recovering back to `pass_through` requires `score >= threshold + hysteresis_band`.

---

## Holistic Risk Classification Tiers

Apiris evaluates multi-dimensional signal severity across CAD pillars, HTTP response codes, and security factors to classify traffic into five standardized operational risk tiers:

| Risk Tier | Visual Badge | Operational Definition & Criteria | Example Scenarios |
|---|---|---|---|
| **LOW** | `✓ LOW` (Green) | All CIA scores nominal ($\ge 0.40$), `pass_through` action, 0 negative security factors. | Clean, healthy 200 OK traffic with consistent schema. |
| **MODERATE** | `⚠ MODERATE` (Yellow) | Single isolated non-critical signal (e.g. 1 cookie header exposure on 200 OK, pacing delay, or single-dimension threshold dip). | `api.weather.gov` returning `Set-Cookie` header. |
| **ELEVATED** | `▲ ELEVATED` (Orange) | Two non-critical warning signals (e.g. 2 exposed headers like Cookie + Auth header), cache fallback (`serve_stale_cache`), or moderate latency jitter. | Response exposing multiple tracking/auth headers or cached fallback. |
| **HIGH** | `✗ HIGH` (Red) | Substantial single-pillar breach (e.g. multiple credentials/auth hints leaked), or multi-pillar degradation without hard failure. | Response leaking multiple auth keys or verbose debug traceback. |
| **CRITICAL** | `🚨 CRITICAL` (White on Red) | Multi-pillar degradation + HTTP 4xx/5xx failure, $\ge 4$ distinct security factors, or hard block (`reject_response`). | `api.nasa.gov` 403 Forbidden with missing key, auth hints, and stack traces. |


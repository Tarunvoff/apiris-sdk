# Changelog

All notable changes to the Apiris SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-08-27

### Added
- **Calibration Foundation**: Synthetic clean traffic calibration corpus (`data/clean_traffic_corpus.json`) and automated calibration methodology script (`scripts/calibrate_thresholds.py`).
- **Backward Compatibility Flag**: `strict_zero_tolerance: bool = False` configuration parameter. Integrators relying on legacy `0.0` default sensitivity can opt in with `strict_zero_tolerance: true`.
- **Contextual Per-API Anomaly Modeling**: Support for per-`api_name` baselines in `AnomalyScorer` with graceful fallback to `_global` baseline (`docs/TRAINING_ANOMALY_MODELS.md`).
- **Graduated Action Selection & Hysteresis**: Added `hysteresis_band` (default `0.05`) to prevent action flapping on borderline noise across decision states.
- **Calibrated Confidence Scoring**: Replaced static and discontinuous breach formulas with a calibrated distance-from-decision-boundary certainty metric.
- **Automated CVE Integrity CI Check**: Script `scripts/validate_cve_data.py` and test `tests/test_cve_validation.py` cross-verifying CVE IDs and vendor attributions against authoritative NVD/GHSA metadata.
- **Intelligence Plane Modules**: Cleanly backported `drift_analyzer.py`, `risk_aggregator.py`, `vendor_profile.py`, and `models.py` into `apiris.intelligence`.
- **Comprehensive Calibration Report**: Checked in empirical before/after calibration metrics in `docs/CALIBRATION_REPORT.md`.
- **Full HTTP Verb Support**: Added `request()`, `post()`, `put()`, `delete()` methods on `ApirisClient`.

### Changed
- **Default Risk Thresholds**: Updated default thresholds from `0.0` to calibrated non-zero values (`integrity_threshold: 0.40`, `availability_threshold: 0.40`, `anomaly_threshold: 0.70`) to eliminate always-maximal-risk false positive readings on clean traffic.
- **Test Suite**: Fixed broken `pytest` collection and added regression suites for clean traffic pass-through, confidence calibration, and CVE integrity.

### Deprecated / Compatibility
- Preserved legacy aliases `CADClient`, `CADResponse`, `CADDecision`, `CADSummary` for seamless drop-in compatibility with pre-v1.0.2 integrations.

---

## [1.0.2] - 2026-02-21
- Expanded CVE database to 47 vendors with 65 vulnerabilities.
- Added rich CLI display with status progress bars and risk classification.

## [1.0.1] - 2026-02-21
- Fixed package asset distribution for offline AI models.
- Zero-dependency offline Isolation Forest and latency predictor integration.

## [1.0.0] - 2026-02-21
- Initial public release of Apiris SDK.

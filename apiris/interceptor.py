from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from .cache import ResponseCache


def _hash_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _mask_sensitive_fields(value: Any, depth: int = 0, max_depth: int = 6) -> Any:
    if depth > max_depth:
        return value
    if isinstance(value, list):
        return [_mask_sensitive_fields(item, depth + 1, max_depth) for item in value]
    if not isinstance(value, dict):
        return value

    patterns = ["password", "secret", "token", "api_key", "api-key", "auth", "cookie", "session", "jwt"]
    result: Dict[str, Any] = {}
    for key, val in value.items():
        if any(pattern in str(key).lower() for pattern in patterns):
            result[key] = "[MASKED]"
        else:
            result[key] = _mask_sensitive_fields(val, depth + 1, max_depth)
    return result


class ResponseInterceptor:
    def apply(self, action: str, response_text: Optional[str], parsed: Any, response_headers: Optional[Dict[str, str]], response_status: Optional[int], cache: Optional[ResponseCache], cache_ttl_ms: int) -> Dict[str, Any]:
        response_headers = response_headers or {}

        if action == "pass_through" or response_status is None:
            return {
                "status": response_status,
                "headers": response_headers,
                "body": response_text,
                "modified": False,
            }

        if action == "mask_sensitive_fields":
            if isinstance(parsed, dict):
                return {
                    "status": response_status,
                    "headers": response_headers,
                    "body": json.dumps(_mask_sensitive_fields(parsed)),
                    "modified": True,
                    "modification": "masked_sensitive_fields",
                }
            return {
                "status": response_status,
                "headers": response_headers,
                "body": response_text,
                "modified": False,
                "modification": "mask_skipped_non_json",
            }

        if action == "serve_stale_cache":
            if not cache:
                return {
                    "status": response_status,
                    "headers": response_headers,
                    "body": response_text,
                    "modified": False,
                    "modification": "cache_unavailable_pass_through",
                    "actionApplied": "pass_through",
                }
            cache_age_ms = int((__import__("time").time() * 1000) - cache.ts)
            if cache_age_ms > cache_ttl_ms:
                return {
                    "status": response_status,
                    "headers": response_headers,
                    "body": response_text,
                    "modified": False,
                    "modification": "cache_expired_pass_through",
                    "actionApplied": "pass_through",
                }
            return {
                "status": cache.status,
                "headers": cache.headers,
                "body": cache.body,
                "modified": True,
                "modification": "served_stale_cache",
                "cacheAgeMs": cache_age_ms,
                "actionApplied": "serve_stale_cache",
            }

        if action == "reject_response":
            return {
                "status": 503,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"error": "integrity_risk"}),
                "modified": True,
                "modification": "rejected",
                "actionApplied": "reject_response",
            }

        if action == "downgrade_fidelity":
            return {
                "status": response_status,
                "headers": {"content-type": "application/json"},
                "body": json.dumps(
                    {
                        "bodyHash": _hash_text(response_text) if response_text else None,
                        "bodyBytes": len(response_text.encode("utf-8")) if response_text else 0,
                        "status": response_status,
                    }
                ),
                "modified": True,
                "modification": "metadata_only",
                "actionApplied": "downgrade_fidelity",
            }

        if action == "delay_response":
            return {
                "status": response_status,
                "headers": response_headers,
                "body": response_text,
                "modified": True,
                "modification": "delayed",
                "actionApplied": "delay_response",
            }

        return {
            "status": response_status,
            "headers": response_headers,
            "body": response_text,
            "modified": False,
            "actionApplied": "pass_through",
        }

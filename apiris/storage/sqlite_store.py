from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

from ..intelligence.models import ServiceProfile, VendorProfile


class SQLiteStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.db_path)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS service_profiles (
                    service_name TEXT PRIMARY KEY,
                    avg_c_score REAL,
                    avg_a_score REAL,
                    avg_d_score REAL,
                    degradation_frequency REAL,
                    rejection_frequency REAL,
                    sample_count INTEGER,
                    updated_at TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vendor_profiles (
                    vendor_name TEXT PRIMARY KEY,
                    vendor_trust_score REAL,
                    integrity_stability REAL,
                    availability_stability REAL,
                    incident_frequency REAL,
                    recovery_speed REAL,
                    updated_at TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cad_time_series (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT,
                    timestamp TEXT,
                    c_score REAL,
                    a_score REAL,
                    d_score REAL,
                    latency_ms INTEGER,
                    schema_changed INTEGER,
                    decision_action TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version TEXT,
                    policy_json TEXT,
                    created_at TEXT
                )
                """
            )
            conn.commit()

    def upsert_service_profile(self, profile: ServiceProfile) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO service_profiles (
                        service_name, avg_c_score, avg_a_score, avg_d_score,
                        degradation_frequency, rejection_frequency, sample_count, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(service_name) DO UPDATE SET
                        avg_c_score=excluded.avg_c_score,
                        avg_a_score=excluded.avg_a_score,
                        avg_d_score=excluded.avg_d_score,
                        degradation_frequency=excluded.degradation_frequency,
                        rejection_frequency=excluded.rejection_frequency,
                        sample_count=excluded.sample_count,
                        updated_at=excluded.updated_at
                    """,
                    (
                        profile.service_name,
                        profile.avg_c_score,
                        profile.avg_a_score,
                        profile.avg_d_score,
                        profile.degradation_frequency,
                        profile.rejection_frequency,
                        profile.sample_count,
                        profile.updated_at,
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def get_service_profiles(self) -> List[ServiceProfile]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT service_name, avg_c_score, avg_a_score, avg_d_score,
                       degradation_frequency, rejection_frequency, sample_count, updated_at
                FROM service_profiles
                """
            ).fetchall()
        return [
            ServiceProfile(
                service_name=row[0],
                avg_c_score=row[1],
                avg_a_score=row[2],
                avg_d_score=row[3],
                degradation_frequency=row[4],
                rejection_frequency=row[5],
                sample_count=row[6],
                updated_at=row[7],
            )
            for row in rows
        ]

    def get_service_profile(self, service_name: str) -> Optional[ServiceProfile]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT service_name, avg_c_score, avg_a_score, avg_d_score,
                       degradation_frequency, rejection_frequency, sample_count, updated_at
                FROM service_profiles WHERE service_name = ?
                """,
                (service_name,),
            ).fetchone()
        if not row:
            return None
        return ServiceProfile(
            service_name=row[0],
            avg_c_score=row[1],
            avg_a_score=row[2],
            avg_d_score=row[3],
            degradation_frequency=row[4],
            rejection_frequency=row[5],
            sample_count=row[6],
            updated_at=row[7],
        )

    def upsert_vendor_profile(self, profile: VendorProfile) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO vendor_profiles (
                        vendor_name, vendor_trust_score, integrity_stability,
                        availability_stability, incident_frequency, recovery_speed, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(vendor_name) DO UPDATE SET
                        vendor_trust_score=excluded.vendor_trust_score,
                        integrity_stability=excluded.integrity_stability,
                        availability_stability=excluded.availability_stability,
                        incident_frequency=excluded.incident_frequency,
                        recovery_speed=excluded.recovery_speed,
                        updated_at=excluded.updated_at
                    """,
                    (
                        profile.vendor_name,
                        profile.vendor_trust_score,
                        profile.integrity_stability,
                        profile.availability_stability,
                        profile.incident_frequency,
                        profile.recovery_speed,
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def get_vendor_profile(self, vendor_name: str) -> Optional[VendorProfile]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT vendor_name, vendor_trust_score, integrity_stability,
                       availability_stability, incident_frequency, recovery_speed
                FROM vendor_profiles WHERE vendor_name = ?
                """,
                (vendor_name,),
            ).fetchone()
        if not row:
            return None
        return VendorProfile(
            vendor_name=row[0],
            vendor_trust_score=row[1],
            integrity_stability=row[2],
            availability_stability=row[3],
            incident_frequency=row[4],
            recovery_speed=row[5],
        )

    def get_vendor_profiles(self) -> List[VendorProfile]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT vendor_name, vendor_trust_score, integrity_stability,
                       availability_stability, incident_frequency, recovery_speed
                FROM vendor_profiles
                """
            ).fetchall()
        return [
            VendorProfile(
                vendor_name=row[0],
                vendor_trust_score=row[1],
                integrity_stability=row[2],
                availability_stability=row[3],
                incident_frequency=row[4],
                recovery_speed=row[5],
            )
            for row in rows
        ]

    def insert_time_series(
        self,
        service_name: str,
        timestamp: str,
        c_score: float,
        a_score: float,
        d_score: float,
        latency_ms: Optional[int],
        schema_changed: Optional[bool],
        decision_action: Optional[str],
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO cad_time_series (
                        service_name, timestamp, c_score, a_score, d_score,
                        latency_ms, schema_changed, decision_action
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        service_name,
                        timestamp,
                        c_score,
                        a_score,
                        d_score,
                        latency_ms,
                        int(schema_changed) if schema_changed is not None else None,
                        decision_action,
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def list_time_series(self, service_name: Optional[str] = None) -> List[dict]:
        with self._connect() as conn:
            if service_name:
                rows = conn.execute(
                    """
                    SELECT service_name, timestamp, c_score, a_score, d_score,
                           latency_ms, schema_changed, decision_action
                    FROM cad_time_series WHERE service_name = ?
                    """,
                    (service_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT service_name, timestamp, c_score, a_score, d_score,
                           latency_ms, schema_changed, decision_action
                    FROM cad_time_series
                    """
                ).fetchall()
        return [
            {
                "service_name": row[0],
                "timestamp": row[1],
                "c_score": row[2],
                "a_score": row[3],
                "d_score": row[4],
                "latency_ms": row[5],
                "schema_changed": bool(row[6]) if row[6] is not None else None,
                "decision_action": row[7],
            }
            for row in rows
        ]

    def insert_policy_version(self, version: str, policy: dict) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO policy_versions (version, policy_json, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        version,
                        json.dumps(policy),
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    ),
                )
                conn.commit()
        except Exception:
            pass

    def list_policy_versions(self) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT version, policy_json, created_at
                FROM policy_versions
                ORDER BY id DESC
                """
            ).fetchall()
        result = []
        for row in rows:
            try:
                policy = json.loads(row[1]) if row[1] else {}
            except json.JSONDecodeError:
                policy = {}
            result.append({"version": row[0], "policy": policy, "created_at": row[2]})
        return result

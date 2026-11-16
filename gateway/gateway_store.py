import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from geo_intelligence import GeoIntelligence


class GatewayStore:
    def __init__(self, db_path: str = "sos_gateway.db") -> None:
        self.db_path = str(Path(db_path))
        self.geo = GeoIntelligence()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()
        # Backfill geospatial fields for databases created before the map feature.
        self.refresh_missing_spatial_fields()

    def _table_columns(self, table: str) -> set[str]:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {str(r["name"]) for r in rows}

    def _ensure_column(self, table: str, column: str, ddl_type: str, default_sql: Optional[str] = None) -> None:
        cols = self._table_columns(table)
        if column in cols:
            return
        sql = f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"
        if default_sql is not None:
            sql += f" DEFAULT {default_sql}"
        self._conn.execute(sql)

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sos_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at_ms INTEGER NOT NULL,
                    sender_peer TEXT NOT NULL,
                    via_ble TEXT NOT NULL,
                    ttl_seen INTEGER NOT NULL,
                    sos_time_ms INTEGER,
                    body TEXT NOT NULL,
                    lat REAL,
                    lon REAL,
                    acc REAL,
                    raw_json TEXT NOT NULL,
                    dedup_key TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_sos_events_received_at
                ON sos_events(received_at_ms DESC);

                CREATE INDEX IF NOT EXISTS idx_sos_events_sender_peer
                ON sos_events(sender_peer);

                CREATE INDEX IF NOT EXISTS idx_sos_events_sos_time
                ON sos_events(sos_time_ms);

                CREATE TABLE IF NOT EXISTS copilot_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    direction TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    stage TEXT,
                    body TEXT NOT NULL,
                    raw_json TEXT,
                    FOREIGN KEY(event_id) REFERENCES sos_events(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_copilot_messages_event_id
                ON copilot_messages(event_id, created_at_ms ASC);
                """
            )

            # Migrations for enriched Smart-City Safety Copilot state.
            self._ensure_column("sos_events", "incident_status", "TEXT", "'new'")
            self._ensure_column("sos_events", "copilot_stage", "TEXT", "'injury'")
            self._ensure_column("sos_events", "injury_status", "TEXT")
            self._ensure_column("sos_events", "mobility_status", "TEXT")
            self._ensure_column("sos_events", "hazard_flags", "TEXT")
            self._ensure_column("sos_events", "people_count", "INTEGER")
            self._ensure_column("sos_events", "severity_score", "INTEGER", "0")
            self._ensure_column("sos_events", "severity_level", "TEXT", "'unknown'")
            self._ensure_column("sos_events", "guidance_text", "TEXT")
            self._ensure_column("sos_events", "triage_summary", "TEXT")
            self._ensure_column("sos_events", "last_contact_ms", "INTEGER")
            self._ensure_column("sos_events", "last_gateway_message_ms", "INTEGER")

            # Migrations for Geospatial Incident Map and Hotspot Intelligence.
            self._ensure_column("sos_events", "coord_status", "TEXT", "'unknown'")
            self._ensure_column("sos_events", "location_quality", "TEXT", "'unknown'")
            self._ensure_column("sos_events", "spatial_confidence", "REAL", "0")
            self._ensure_column("sos_events", "geocell", "TEXT")
            self._ensure_column("sos_events", "map_lat", "REAL")
            self._ensure_column("sos_events", "map_lon", "REAL")

            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sos_events_geo_time ON sos_events(coord_status, received_at_ms DESC)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sos_events_geocell ON sos_events(geocell, received_at_ms DESC)"
            )

            # Rename the old post-triage status to a clearer responder-facing name.
            self._conn.execute("UPDATE sos_events SET incident_status = 'triage_completed' WHERE incident_status = 'monitoring'")
            self._conn.execute("UPDATE sos_events SET copilot_stage = 'triage_completed' WHERE copilot_stage = 'monitoring'")
            self._conn.execute("UPDATE copilot_messages SET stage = 'triage_completed' WHERE stage = 'monitoring'")
            self._conn.commit()

    def insert_sos_event(
        self,
        *,
        sender_peer: str,
        via_ble: str,
        ttl_seen: int,
        sos: Dict[str, Any],
        dedup_key: str,
    ) -> Tuple[bool, int]:
        received_at_ms = int(time.time() * 1000)
        raw_json = json.dumps(sos, ensure_ascii=False, separators=(",", ":"))
        geo = self.geo.enrich_sos(sos)

        with self._lock:
            try:
                cur = self._conn.execute(
                    """
                    INSERT INTO sos_events (
                        received_at_ms,
                        sender_peer,
                        via_ble,
                        ttl_seen,
                        sos_time_ms,
                        body,
                        lat,
                        lon,
                        acc,
                        raw_json,
                        dedup_key,
                        incident_status,
                        copilot_stage,
                        severity_score,
                        severity_level,
                        last_contact_ms,
                        coord_status,
                        location_quality,
                        spatial_confidence,
                        geocell,
                        map_lat,
                        map_lon
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', 'injury', 0, 'unknown', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        received_at_ms,
                        sender_peer,
                        via_ble,
                        ttl_seen,
                        sos.get("time"),
                        sos.get("body", ""),
                        sos.get("lat"),
                        sos.get("lon"),
                        sos.get("acc"),
                        raw_json,
                        dedup_key,
                        received_at_ms,
                        geo.get("coord_status"),
                        geo.get("location_quality"),
                        geo.get("spatial_confidence"),
                        geo.get("geocell"),
                        geo.get("map_lat"),
                        geo.get("map_lon"),
                    ),
                )
                self._conn.commit()
                return True, int(cur.lastrowid)
            except sqlite3.IntegrityError:
                row = self._conn.execute(
                    "SELECT id FROM sos_events WHERE dedup_key = ?",
                    (dedup_key,),
                ).fetchone()
                return False, int(row["id"]) if row else -1

    def add_copilot_message(
        self,
        *,
        event_id: int,
        direction: str,
        kind: str,
        body: str,
        stage: Optional[str] = None,
        raw_json: Optional[Dict[str, Any] | str] = None,
        created_at_ms: Optional[int] = None,
    ) -> int:
        created_at_ms = int(created_at_ms or time.time() * 1000)
        if isinstance(raw_json, dict):
            raw_json_str = json.dumps(raw_json, ensure_ascii=False, separators=(",", ":"))
        else:
            raw_json_str = raw_json
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO copilot_messages (event_id, created_at_ms, direction, kind, stage, body, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, created_at_ms, direction, kind, stage, body, raw_json_str),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def update_event_fields(self, event_id: int, **fields: Any) -> None:
        if not fields:
            return
        allowed = {
            "incident_status", "copilot_stage", "injury_status", "mobility_status",
            "hazard_flags", "people_count", "severity_score", "severity_level",
            "guidance_text", "triage_summary", "last_contact_ms", "last_gateway_message_ms",
            "coord_status", "location_quality", "spatial_confidence", "geocell", "map_lat", "map_lon",
        }
        payload = {k: v for k, v in fields.items() if k in allowed}
        if not payload:
            return
        cols = ", ".join(f"{k} = ?" for k in payload.keys())
        values = list(payload.values()) + [event_id]
        with self._lock:
            self._conn.execute(f"UPDATE sos_events SET {cols} WHERE id = ?", values)
            self._conn.commit()

    def refresh_spatial_fields(self, event_id: int) -> None:
        event = self.get_event(event_id)
        if not event:
            return
        geo = self.geo.enrich_sos(event)
        self.update_event_fields(event_id, **geo)

    def refresh_missing_spatial_fields(self) -> int:
        """Backfill spatial fields for existing rows after a schema migration."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, lat, lon, acc, raw_json
                FROM sos_events
                WHERE coord_status IS NULL
                   OR coord_status = 'unknown'
                   OR (lat IS NOT NULL AND lon IS NOT NULL AND (map_lat IS NULL OR map_lon IS NULL))
                LIMIT 10000
                """
            ).fetchall()

        count = 0
        for row in rows:
            event = dict(row)
            raw = event.get("raw_json")
            if raw:
                try:
                    raw_obj = json.loads(raw)
                    if isinstance(raw_obj, dict):
                        event.update(raw_obj)
                except Exception:
                    pass
            geo = self.geo.enrich_sos(event)
            self.update_event_fields(int(event["id"]), **geo)
            count += 1
        if count:
            print(f"[GEO] backfilled spatial fields for {count} existing SOS event(s)")
        return count

    def refresh_all_spatial_fields(self) -> int:
        events = self.list_recent_events(limit=10000)
        count = 0
        for event in events:
            self.refresh_spatial_fields(int(event["id"]))
            count += 1
        return count

    def get_event(self, event_id: int) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM sos_events WHERE id = ?", (event_id,)).fetchone()
        return self._row_to_event(row) if row else None

    def get_active_event_for_sender(self, sender_peer: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM sos_events
                WHERE sender_peer = ?
                  AND incident_status IN ('new', 'triage_active', 'triage_completed')
                ORDER BY received_at_ms DESC
                LIMIT 1
                """,
                (sender_peer,),
            ).fetchone()
        return self._row_to_event(row) if row else None

    def list_recent_events(self, limit: int = 20) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    id, received_at_ms, sender_peer, via_ble, ttl_seen, sos_time_ms, body,
                    lat, lon, acc, raw_json, dedup_key,
                    incident_status, copilot_stage, injury_status, mobility_status,
                    hazard_flags, people_count, severity_score, severity_level,
                    guidance_text, triage_summary, last_contact_ms, last_gateway_message_ms,
                    coord_status, location_quality, spatial_confidence,
                    geocell, map_lat, map_lon
                FROM sos_events
                ORDER BY received_at_ms DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def list_recent_spatial_events(self, *, limit: int = 500, window_minutes: Optional[int] = None) -> List[dict]:
        params: List[Any] = []
        where = "coord_status = 'valid'"
        if window_minutes is not None and window_minutes > 0:
            since_ms = int(time.time() * 1000) - int(window_minutes * 60 * 1000)
            where += " AND received_at_ms >= ?"
            params.append(since_ms)
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM sos_events
                WHERE {where}
                ORDER BY received_at_ms DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def list_copilot_messages(self, event_id: int, limit: int = 200) -> List[dict]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, event_id, created_at_ms, direction, kind, stage, body, raw_json
                FROM copilot_messages
                WHERE event_id = ?
                ORDER BY created_at_ms ASC
                LIMIT ?
                """,
                (event_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            raw = item.get("raw_json")
            if raw:
                try:
                    item["raw_json"] = json.loads(raw)
                except Exception:
                    pass
            out.append(item)
        return out

    def severity_counts(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT severity_level, COUNT(*) AS c
                FROM sos_events
                GROUP BY severity_level
                """
            ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for r in rows:
            counts[str(r["severity_level"] or "unknown")] = int(r["c"])
        return counts

    def location_quality_counts(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT COALESCE(location_quality, 'unknown') AS quality, COUNT(*) AS c
                FROM sos_events
                WHERE coord_status = 'valid'
                GROUP BY COALESCE(location_quality, 'unknown')
                """
            ).fetchall()
        return {str(r["quality"]): int(r["c"]) for r in rows}

    def _row_to_event(self, row: sqlite3.Row) -> dict:
        item = dict(row)
        raw = item.get("raw_json")
        if raw:
            try:
                item["raw_json"] = json.loads(raw)
            except Exception:
                pass
        hazards = item.get("hazard_flags")
        if hazards:
            try:
                item["hazard_flags"] = json.loads(hazards)
            except Exception:
                item["hazard_flags"] = [h.strip() for h in str(hazards).split(",") if h.strip()]
        else:
            item["hazard_flags"] = []
        return item

    def close(self) -> None:
        with self._lock:
            self._conn.close()

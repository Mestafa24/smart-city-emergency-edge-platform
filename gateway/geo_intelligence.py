"""
Geospatial Incident Map and Hotspot Intelligence for the
Smart-City Emergency Edge Platform.

This module intentionally uses only the Python standard library so it can run
on the Raspberry Pi gateway without installing GIS/database extensions.

Core responsibilities:
- validate SOS latitude/longitude/accuracy fields
- assign coarse location quality
- assign a stable grid/geocell identifier for indexing
- compute recent hotspot clusters from stored SOS incidents
- export incidents/hotspots as GeoJSON for the Flask dashboard

Coordinates are always [lat, lon] internally and [lon, lat] in GeoJSON.
"""

from __future__ import annotations

import math
import statistics
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

EARTH_RADIUS_M = 6_371_000.0
DEFAULT_GRID_M = 75.0
DEFAULT_HOTSPOT_WINDOW_MIN = 60
DEFAULT_HOTSPOT_RADIUS_M = 50.0
# Backward-compatible alias used by older API/frontend code.
DEFAULT_HOTSPOT_GRID_M = DEFAULT_HOTSPOT_RADIUS_M
DEFAULT_MIN_HOTSPOT_EVENTS = 2

SEVERITY_WEIGHTS = {
    "unknown": 0,
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 10,
}

SEVERITY_COLORS = {
    "critical": "#b00020",
    "high": "#d35400",
    "medium": "#d4ac0d",
    "low": "#1e8449",
    "unknown": "#7f8c8d",
}


def _to_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        out = float(value)
        if math.isnan(out) or math.isinf(out):
            return None
        return out
    except Exception:
        return None


def is_valid_coordinate(lat: Any, lon: Any) -> bool:
    lat_f = _to_float(lat)
    lon_f = _to_float(lon)
    if lat_f is None or lon_f is None:
        return False
    if not (-90.0 <= lat_f <= 90.0 and -180.0 <= lon_f <= 180.0):
        return False
    # A frequent placeholder from failed GPS/location providers.
    if abs(lat_f) < 0.000001 and abs(lon_f) < 0.000001:
        return False
    return True


def location_quality(acc: Any) -> Tuple[str, float]:
    """Return (quality label, confidence score 0..1) from location accuracy."""
    acc_f = _to_float(acc)
    if acc_f is None or acc_f < 0:
        return "unknown", 0.55
    if acc_f <= 20:
        return "precise", 0.98
    if acc_f <= 75:
        return "usable", 0.82
    if acc_f <= 250:
        return "approximate", 0.55
    return "weak", 0.30


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lam = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lam / 2.0) ** 2
    return 2.0 * EARTH_RADIUS_M * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def latlon_to_xy_m(lat: float, lon: float, origin_lat: float, origin_lon: float) -> Tuple[float, float]:
    """Small-area equirectangular projection, good enough for campus/building maps."""
    x = math.radians(lon - origin_lon) * EARTH_RADIUS_M * math.cos(math.radians(origin_lat))
    y = math.radians(lat - origin_lat) * EARTH_RADIUS_M
    return x, y


def xy_to_latlon_m(x: float, y: float, origin_lat: float, origin_lon: float) -> Tuple[float, float]:
    lat = origin_lat + math.degrees(y / EARTH_RADIUS_M)
    lon = origin_lon + math.degrees(x / (EARTH_RADIUS_M * math.cos(math.radians(origin_lat))))
    return lat, lon


def geocell_for(lat: float, lon: float, cell_m: float = DEFAULT_GRID_M) -> str:
    """Stable approximate grid cell. Useful for indexing and simple filtering."""
    lat_step = cell_m / 111_320.0
    lon_step = cell_m / max(1.0, 111_320.0 * math.cos(math.radians(lat)))
    lat_idx = math.floor(lat / lat_step)
    lon_idx = math.floor(lon / lon_step)
    return f"g{int(cell_m)}:{lat_idx}:{lon_idx}"


class GeoIntelligence:
    def enrich_sos(self, sos: Dict[str, Any]) -> Dict[str, Any]:
        lat = _to_float(sos.get("lat"))
        lon = _to_float(sos.get("lon"))
        acc = _to_float(sos.get("acc"))

        if not is_valid_coordinate(lat, lon):
            return {
                "coord_status": "missing_or_invalid",
                "location_quality": "none",
                "spatial_confidence": 0.0,
                "geocell": None,
                "map_lat": None,
                "map_lon": None,
            }

        assert lat is not None and lon is not None
        quality, confidence = location_quality(acc)
        return {
            "coord_status": "valid",
            "location_quality": quality,
            "spatial_confidence": confidence,
            "geocell": geocell_for(lat, lon),
            "map_lat": lat,
            "map_lon": lon,
        }

    def incidents_geojson(self, events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        features = []
        for e in events:
            lat = _to_float(e.get("map_lat", e.get("lat")))
            lon = _to_float(e.get("map_lon", e.get("lon")))
            if not is_valid_coordinate(lat, lon):
                continue
            props = dict(e)
            props["color"] = SEVERITY_COLORS.get(str(e.get("severity_level") or "unknown"), SEVERITY_COLORS["unknown"])
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": props,
            })
        return {"type": "FeatureCollection", "features": features}

    def compute_hotspots(
        self,
        events: Iterable[Dict[str, Any]],
        *,
        window_minutes: int = DEFAULT_HOTSPOT_WINDOW_MIN,
        cluster_radius_m: Optional[float] = None,
        grid_m: Optional[float] = None,
        min_events: int = DEFAULT_MIN_HOTSPOT_EVENTS,
        now_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Compute proximity-based hotspot clusters.

        A hotspot is formed when at least `min_events` valid incidents are
        connected by physical distance: each linked pair is within
        `cluster_radius_m` metres of each other. `grid_m` remains accepted as a
        backwards-compatible alias for older API calls.
        """
        now_ms = int(now_ms or time.time() * 1000)
        since_ms = now_ms - int(window_minutes * 60 * 1000)
        radius_m = float(cluster_radius_m if cluster_radius_m is not None else (grid_m if grid_m is not None else DEFAULT_HOTSPOT_RADIUS_M))
        radius_m = max(1.0, radius_m)
        candidates: List[Dict[str, Any]] = []

        for e in events:
            lat = _to_float(e.get("map_lat", e.get("lat")))
            lon = _to_float(e.get("map_lon", e.get("lon")))
            if not is_valid_coordinate(lat, lon):
                continue
            received = int(e.get("received_at_ms") or 0)
            if received < since_ms:
                continue
            item = dict(e)
            item["_lat"] = lat
            item["_lon"] = lon
            candidates.append(item)

        if len(candidates) < min_events:
            return []

        origin_lat = statistics.median(float(e["_lat"]) for e in candidates)
        origin_lon = statistics.median(float(e["_lon"]) for e in candidates)

        for e in candidates:
            x, y = latlon_to_xy_m(float(e["_lat"]), float(e["_lon"]), origin_lat, origin_lon)
            e["_x"] = x
            e["_y"] = y

        n = len(candidates)
        parent = list(range(n))
        rank = [0] * n

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra == rb:
                return
            if rank[ra] < rank[rb]:
                parent[ra] = rb
            elif rank[ra] > rank[rb]:
                parent[rb] = ra
            else:
                parent[rb] = ra
                rank[ra] += 1

        cell = radius_m
        buckets: Dict[Tuple[int, int], List[int]] = {}
        for idx, e in enumerate(candidates):
            bx = math.floor(float(e["_x"]) / cell)
            by = math.floor(float(e["_y"]) / cell)
            buckets.setdefault((bx, by), []).append(idx)

        radius_sq = radius_m * radius_m
        for idx, e in enumerate(candidates):
            bx = math.floor(float(e["_x"]) / cell)
            by = math.floor(float(e["_y"]) / cell)
            for nx in (bx - 1, bx, bx + 1):
                for ny in (by - 1, by, by + 1):
                    for j in buckets.get((nx, ny), []):
                        if j <= idx:
                            continue
                        other = candidates[j]
                        dx = float(e["_x"]) - float(other["_x"])
                        dy = float(e["_y"]) - float(other["_y"])
                        if dx * dx + dy * dy <= radius_sq:
                            union(idx, j)

        components: Dict[int, List[Dict[str, Any]]] = {}
        for idx, e in enumerate(candidates):
            components.setdefault(find(idx), []).append(e)

        hotspots: List[Dict[str, Any]] = []
        hotspot_index = 1
        for group in components.values():
            if len(group) < min_events:
                continue

            weights = []
            for e in group:
                sev = str(e.get("severity_level") or "unknown")
                weights.append(max(1.0, float(SEVERITY_WEIGHTS.get(sev, 0))))
            weight_sum = sum(weights) or float(len(group))
            cx = sum(float(e["_x"]) * w for e, w in zip(group, weights)) / weight_sum
            cy = sum(float(e["_y"]) * w for e, w in zip(group, weights)) / weight_sum
            c_lat, c_lon = xy_to_latlon_m(cx, cy, origin_lat, origin_lon)

            distances = [math.hypot(float(e["_x"]) - cx, float(e["_y"]) - cy) for e in group]
            accs = [_to_float(e.get("acc")) or 0.0 for e in group]
            acc_buffer = min(max(accs or [0.0]), 60.0)
            radius_display_m = max(radius_m, max(distances or [0.0]) + acc_buffer)

            severities = [str(e.get("severity_level") or "unknown") for e in group]
            max_level = max(severities, key=lambda s: SEVERITY_WEIGHTS.get(s, 0))
            total_severity_score = sum(int(e.get("severity_score") or 0) for e in group)
            unique_senders = len({str(e.get("sender_peer") or "") for e in group})
            recent_bonus = sum(1 for e in group if int(e.get("received_at_ms") or 0) >= now_ms - 15 * 60 * 1000)
            hazard_count = sum(len(e.get("hazard_flags") or []) for e in group)
            score = len(group) * 4 + unique_senders * 2 + total_severity_score + recent_bonus * 2 + hazard_count

            if score >= 24 or max_level == "critical":
                level = "critical"
            elif score >= 16 or max_level == "high":
                level = "high"
            elif score >= 9 or max_level == "medium":
                level = "medium"
            else:
                level = "low"

            sorted_group = sorted(group, key=lambda r: int(r.get("received_at_ms") or 0), reverse=True)
            event_ids = [int(e["id"]) for e in sorted_group if e.get("id") is not None]
            max_pair_distance = 0.0
            if len(group) > 1:
                for i in range(len(group)):
                    for j in range(i + 1, len(group)):
                        d = math.hypot(float(group[i]["_x"]) - float(group[j]["_x"]), float(group[i]["_y"]) - float(group[j]["_y"]))
                        max_pair_distance = max(max_pair_distance, d)

            hotspots.append({
                "id": f"hotspot_{hotspot_index}",
                "lat": c_lat,
                "lon": c_lon,
                "radius_m": round(radius_display_m, 1),
                "cluster_radius_m": round(radius_m, 1),
                "max_pair_distance_m": round(max_pair_distance, 1),
                "event_count": len(group),
                "unique_senders": unique_senders,
                "severity_score": int(score),
                "severity_level": level,
                "max_incident_severity": max_level,
                "event_ids": event_ids,
                "newest_received_at_ms": max(int(e.get("received_at_ms") or 0) for e in group),
                "oldest_received_at_ms": min(int(e.get("received_at_ms") or 0) for e in group),
                "window_minutes": window_minutes,
                "clustering_method": "distance_connected_components",
            })
            hotspot_index += 1

        hotspots.sort(key=lambda h: (int(h["severity_score"]), int(h["event_count"]), int(h["newest_received_at_ms"])), reverse=True)
        for i, h in enumerate(hotspots, start=1):
            h["id"] = f"hotspot_{i}"
        return hotspots

    def hotspots_geojson(self, hotspots: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        features = []
        for h in hotspots:
            lat = _to_float(h.get("lat"))
            lon = _to_float(h.get("lon"))
            if lat is None or lon is None:
                continue
            props = dict(h)
            props["color"] = SEVERITY_COLORS.get(str(h.get("severity_level") or "unknown"), SEVERITY_COLORS["unknown"])
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": props,
            })
        return {"type": "FeatureCollection", "features": features}

    def spatial_summary(self, events: Iterable[Dict[str, Any]], hotspots: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        events_list = list(events)
        hotspots_list = list(hotspots)
        mapped = [e for e in events_list if is_valid_coordinate(e.get("map_lat", e.get("lat")), e.get("map_lon", e.get("lon")))]
        quality_counts: Dict[str, int] = {}
        for e in mapped:
            q = str(e.get("location_quality") or "unknown")
            quality_counts[q] = quality_counts.get(q, 0) + 1
        return {
            "event_count": len(events_list),
            "mapped_event_count": len(mapped),
            "hotspot_count": len(hotspots_list),
            "location_quality_counts": quality_counts,
        }

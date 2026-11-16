from __future__ import annotations

import html

from flask import Flask, jsonify, request, Response

from gateway_store import GatewayStore

app = Flask(__name__)
store = GatewayStore("sos_gateway.db")
geo = store.geo


def _int_arg(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(request.args.get(name, str(default)))
    except ValueError:
        value = default
    return max(low, min(value, high))


def _float_arg(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(request.args.get(name, str(default)))
    except ValueError:
        value = default
    return max(low, min(value, high))


def _sev_badge(level: str) -> str:
    colors = {
        "critical": "#b00020",
        "high": "#d35400",
        "medium": "#d4ac0d",
        "low": "#1e8449",
        "unknown": "#7f8c8d",
    }
    return f'<span style="padding:4px 8px;border-radius:999px;background:{colors.get(level, "#7f8c8d")};color:white;font-size:12px;">{html.escape(level.upper())}</span>'


@app.get("/health")
def health():
    recent = store.list_recent_events(limit=500)
    hotspots = geo.compute_hotspots(recent, window_minutes=60)
    return jsonify({
        "status": "ok",
        "service": "smart-city-emergency-edge-platform",
        "severity_counts": store.severity_counts(),
        "location_quality_counts": store.location_quality_counts(),
        "hotspot_count_last_60m": len(hotspots),
    })


@app.get("/events")
def events():
    limit = _int_arg("limit", 20, 1, 1000)
    return jsonify(store.list_recent_events(limit=limit))


@app.get("/events/latest")
def events_latest():
    rows = store.list_recent_events(limit=1)
    if not rows:
        return jsonify({"message": "no events yet"}), 404
    return jsonify(rows[0])


@app.get("/events/<int:event_id>")
def event_by_id(event_id: int):
    event = store.get_event(event_id)
    if not event:
        return jsonify({"message": "event not found"}), 404
    if request.args.get("include_messages") == "1":
        event["messages"] = store.list_copilot_messages(event_id)
    return jsonify(event)


@app.get("/events/<int:event_id>/messages")
def event_messages(event_id: int):
    return jsonify(store.list_copilot_messages(event_id))


@app.get("/geo/incidents")
def geo_incidents():
    """GeoJSON endpoint for mapped SOS incidents."""
    limit = _int_arg("limit", 500, 1, 5000)
    window = _int_arg("window_minutes", 60, 1, 10080)
    rows = store.list_recent_spatial_events(limit=limit, window_minutes=window)
    return jsonify(geo.incidents_geojson(rows))


@app.get("/geo/hotspots")
def geo_hotspots():
    limit = _int_arg("limit", 1000, 1, 5000)
    window = _int_arg("window_minutes", 60, 1, 10080)
    # New name: radius_m. Old name grid_m is still accepted so older URLs keep working.
    if "radius_m" in request.args:
        radius_m = _float_arg("radius_m", 50.0, 1.0, 1000.0)
    else:
        radius_m = _float_arg("grid_m", 50.0, 1.0, 1000.0)
    min_events = _int_arg("min_events", 2, 2, 20)
    rows = store.list_recent_events(limit=limit)
    hotspots = geo.compute_hotspots(rows, window_minutes=window, cluster_radius_m=radius_m, min_events=min_events)
    as_geojson = request.args.get("format") == "geojson"
    if as_geojson:
        return jsonify(geo.hotspots_geojson(hotspots))
    return jsonify({
        "window_minutes": window,
        "radius_m": radius_m,
        "grid_m": radius_m,  # backwards-compatible response field
        "min_events": min_events,
        "clustering_method": "distance_connected_components",
        "hotspots": hotspots,
    })


@app.get("/geo/summary")
def geo_summary():
    limit = _int_arg("limit", 1000, 1, 5000)
    window = _int_arg("window_minutes", 60, 1, 10080)
    rows = store.list_recent_events(limit=limit)
    hotspots = geo.compute_hotspots(rows, window_minutes=window)
    summary = geo.spatial_summary(rows, hotspots)
    summary["severity_counts"] = store.severity_counts()
    return jsonify(summary)


def _table_dashboard() -> str:
    rows = store.list_recent_events(limit=50)
    counts = store.severity_counts()

    cards = "".join(
        f"""
        <div class="stat">
            <div class="label">{html.escape(level.title())}</div>
            <div class="value">{count}</div>
        </div>
        """
        for level, count in counts.items()
    )

    body_rows = []
    for row in rows:
        hazards = ", ".join(row.get("hazard_flags") or []) or "—"
        quality = html.escape(str(row.get("location_quality") or "unknown"))
        body_rows.append(f"""
        <tr>
            <td>{row["id"]}</td>
            <td>{_sev_badge(str(row.get("severity_level") or "unknown"))}</td>
            <td>{html.escape(str(row.get("incident_status") or "new"))}</td>
            <td>{html.escape(str(row["sender_peer"]))}</td>
            <td>{html.escape(str(row["body"]))}</td>
            <td>{quality}</td>
            <td>{html.escape(str(row.get("injury_status") or "—"))}</td>
            <td>{html.escape(str(row.get("mobility_status") or "—"))}</td>
            <td>{html.escape(hazards)}</td>
            <td>{html.escape(str(row.get("people_count") or "—"))}</td>
        </tr>
        """)

    page = f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Smart-City Emergency Edge Platform</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 24px; background: #f7f7f7; color: #1e1e1e; }}
            h1 {{ color: #b00020; margin: 0 0 8px 0; }}
            a {{ color: #b00020; }}
            .card {{ background: white; padding: 16px; border-radius: 14px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-top: 12px; }}
            .stat {{ background: #fafafa; border: 1px solid #eee; border-radius: 12px; padding: 12px; }}
            .stat .label {{ color: #666; font-size: 12px; }}
            .stat .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 14px; vertical-align: top; }}
            th {{ background: #b00020; color: white; }}
            tr:nth-child(even) {{ background: #fafafa; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Smart-City Emergency Edge Platform</h1>
            <p>Responder console for SOS incidents captured from the BitChat mesh, enriched by the Gateway Safety Copilot and geospatial hotspot intelligence.</p>
            <p><a href="/map"><strong>Open live geospatial incident map</strong></a></p>
            <div class="stats">{cards}</div>
        </div>

        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Sender Peer</th>
                        <th>SOS Body</th>
                        <th>Location Quality</th>
                        <th>Injury</th>
                        <th>Mobility</th>
                        <th>Hazards</th>
                        <th>People</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(body_rows) if body_rows else '<tr><td colspan="10">No SOS events yet</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    return page


@app.get("/")
def dashboard():
    return Response(_table_dashboard(), mimetype="text/html")


@app.get("/map")
def map_dashboard():
    return Response(MAP_DASHBOARD_HTML, mimetype="text/html")


MAP_DASHBOARD_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Live Incident Map · Smart-City Emergency Edge Platform</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <style>
    :root {
      --critical: #b00020; --high: #d35400; --medium: #d4ac0d; --low: #1e8449; --unknown: #7f8c8d;
      --ink: #17191c; --muted: #68707a; --card: #ffffff; --bg: #eef1f4; --line: #d8dde3; --soft: #f8f9fb;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--ink); }
    header { background: #15171a; color: white; padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
    header h1 { font-size: 20px; margin: 0; }
    header .sub { color: #cfd4da; font-size: 13px; margin-top: 3px; }
    a { color: #b00020; } header a { color: white; }
    .controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 13px; }
    .controls input, .controls select, .controls button { border: 1px solid #555; border-radius: 10px; padding: 7px 9px; background: white; color: #111; }
    .controls button { cursor: pointer; }
    main { display: grid; grid-template-columns: minmax(360px, 1fr) 410px; gap: 14px; padding: 14px; min-height: calc(100vh - 74px); }
    .panel, .map-card { background: var(--card); border-radius: 16px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); overflow: hidden; }
    .map-card { position: relative; min-height: 690px; border: 1px solid var(--line); }
    #map { position: absolute; inset: 0; background: #dde5ea; z-index: 1; }
    #fallbackMap { position: absolute; inset: 0; z-index: 2; display: none; overflow: hidden; background:
      linear-gradient(90deg, rgba(30,60,90,0.12) 1px, transparent 1px),
      linear-gradient(rgba(30,60,90,0.12) 1px, transparent 1px),
      radial-gradient(circle at 50% 50%, #ffffff, #dfe8ee 78%);
      background-size: 56px 56px, 56px 56px, auto; }
    #empty, #errorBox { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); text-align: center; background: rgba(255,255,255,0.96); border: 1px dashed var(--line); border-radius: 16px; padding: 20px; max-width: 520px; z-index: 80; box-shadow: 0 6px 24px rgba(0,0,0,0.10); }
    #errorBox { display: none; border-color: #b00020; color: #4a000c; }
    .legend { position: absolute; left: 14px; bottom: 14px; z-index: 70; background: rgba(255,255,255,0.95); border: 1px solid var(--line); border-radius: 14px; padding: 10px 12px; font-size: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .legend-row { display: flex; align-items: center; gap: 7px; margin: 5px 0; }
    .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; flex: 0 0 auto; }
    .legend-accuracy { width: 18px; height: 18px; border-radius: 50%; border: 1.5px dashed rgba(20,40,60,0.65); display: inline-block; flex: 0 0 auto; }
    .legend-hotspot { width: 22px; height: 22px; border-radius: 50%; border: 2px solid rgba(176,0,32,0.55); background: rgba(176,0,32,0.16); display: inline-block; flex: 0 0 auto; }
    .scale { position: absolute; right: 14px; bottom: 14px; z-index: 70; background: rgba(255,255,255,0.95); border: 1px solid var(--line); border-radius: 14px; padding: 10px 12px; font-size: 12px; }
    .fallback-marker { position: absolute; width: 22px; height: 22px; transform: translate(-50%, -50%); border-radius: 50%; border: 3px solid white; box-shadow: 0 2px 8px rgba(0,0,0,0.35); cursor: pointer; z-index: 30; }
    .fallback-marker::after { content: attr(data-id); position: absolute; left: 19px; top: -8px; background: rgba(255,255,255,0.96); border: 1px solid #ddd; border-radius: 999px; padding: 2px 6px; font-size: 11px; color: #111; white-space: nowrap; }
    .fallback-ring { position: absolute; border: 1px dashed rgba(20,40,60,0.45); border-radius: 50%; transform: translate(-50%, -50%); pointer-events: none; z-index: 15; }
    .fallback-hotspot { position: absolute; transform: translate(-50%, -50%); border-radius: 50%; border: 2px solid rgba(176,0,32,0.45); background: rgba(176,0,32,0.16); cursor: pointer; z-index: 10; display: flex; align-items: center; justify-content: center; font-weight: 800; color: #3a000a; text-shadow: 0 1px 0 rgba(255,255,255,0.75); }
    .axis-label { position: absolute; z-index: 4; color: rgba(20,40,60,0.55); font-size: 12px; background: rgba(255,255,255,0.75); border-radius: 999px; padding: 3px 7px; }
    .side-header { padding: 14px 16px; border-bottom: 1px solid var(--line); }
    .side-header h2 { margin: 0; font-size: 18px; }
    .side-header p { margin: 5px 0 0; color: var(--muted); font-size: 13px; }
    .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; padding: 14px; border-bottom: 1px solid var(--line); }
    .stat { background: var(--soft); border: 1px solid #edf0f2; border-radius: 12px; padding: 10px; }
    .stat .label { color: var(--muted); font-size: 12px; }
    .stat .value { font-size: 24px; font-weight: 800; margin-top: 4px; }
    .section { padding: 14px 16px; border-bottom: 1px solid var(--line); }
    .section h3 { margin: 0 0 10px 0; font-size: 15px; }
    .item { border: 1px solid #e5e8eb; border-radius: 12px; padding: 10px; margin-bottom: 10px; background: #fff; cursor: pointer; }
    .item:hover { background: #fafafa; border-color: #cbd3dc; }
    .item strong { display: block; margin-bottom: 4px; }
    .item .meta { color: var(--muted); font-size: 12px; line-height: 1.45; }
    .badge { display: inline-block; color: white; border-radius: 999px; padding: 2px 7px; font-size: 11px; margin-right: 4px; text-transform: uppercase; }
    .details { padding: 14px 16px; min-height: 160px; }
    .details pre { white-space: pre-wrap; background: var(--soft); border: 1px solid #edf0f2; border-radius: 12px; padding: 10px; font-size: 12px; overflow: auto; max-height: 340px; }
    .leaflet-popup-content { font-family: Arial, sans-serif; }
    @media (max-width: 980px) { main { grid-template-columns: 1fr; } .map-card { min-height: 580px; } }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Live Geospatial Incident Map</h1>
      <div class="sub">SOS locations, recent clusters, and hotspot intelligence from the BitChat gateway</div>
    </div>
    <div class="controls">
      <label>Time window
        <select id="window">
          <option value="60" selected>Last hour</option>
          <option value="360">Last 6 hours</option>
          <option value="1440">Last 24 hours</option>
          <option value="10080">Last 7 days</option>
        </select>
      </label>
      <label>Cluster radius (m) <input id="grid" type="number" min="1" max="1000" value="50" style="width:76px"></label>
      <label>Min cluster <input id="minEvents" type="number" min="2" max="20" value="2" style="width:64px"></label>
      <button onclick="loadData()">Refresh</button>
      <a href="/">Table</a>
    </div>
  </header>

  <main>
    <section class="map-card">
      <div id="map"></div>
      <div id="fallbackMap"></div>
      <div id="empty" style="display:none">
        <h2>No incidents in this time window</h2>
        <p>Try changing the window to <strong>Last 7 days</strong> or send a fresh SOS from Android.</p>
      </div>
      <div id="errorBox"></div>
      <div class="legend">
        <strong>Legend</strong>
        <div class="legend-row"><span class="dot" style="background:var(--critical)"></span>Critical incident</div>
        <div class="legend-row"><span class="dot" style="background:var(--high)"></span>High severity incident</div>
        <div class="legend-row"><span class="dot" style="background:var(--medium)"></span>Medium severity incident</div>
        <div class="legend-row"><span class="dot" style="background:var(--low)"></span>Low severity incident</div>
        <div class="legend-row"><span class="dot" style="background:var(--unknown)"></span>Unknown severity incident</div>
        <div class="legend-row"><span class="legend-accuracy"></span>Grey dashed circle = phone GPS accuracy estimate</div>
        <div class="legend-row"><span class="legend-hotspot"></span>Large transparent circle = hotspot/cluster of nearby recent incidents</div>
      </div>
      <div class="scale" id="scale">Scale: —</div>
    </section>

    <aside class="panel">
      <div class="side-header">
        <h2>Responder Spatial Console</h2>
        <p id="status">Loading…</p>
      </div>
      <div class="stats-grid">
        <div class="stat"><div class="label">Incidents</div><div class="value" id="mappedCount">0</div></div>
        <div class="stat"><div class="label">Hotspots</div><div class="value" id="hotspotCount">0</div></div>
      </div>
      <div class="section">
        <h3>Recent hotspots</h3>
        <div id="hotspotList"></div>
      </div>
      <div class="section">
        <h3>Recent incidents</h3>
        <div id="incidentList"></div>
      </div>
      <div class="details">
        <h3>Selected item</h3>
        <div id="details">Click an incident marker or hotspot.</div>
      </div>
    </aside>
  </main>

  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
const COLORS = { critical: '#b00020', high: '#d35400', medium: '#d4ac0d', low: '#1e8449', unknown: '#7f8c8d' };
let state = { features: [], hotspots: [], summary: {} };
let leafletMap = null;
let incidentLayer = null;
let hotspotLayer = null;
let tileLayer = null;
let realMapTilesLoaded = false;
let tileFailureFallbackStarted = false;

function esc(value) { return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function age(ms) { if (!ms) return 'unknown time'; const diff = Math.max(0, Date.now() - Number(ms)); const min = Math.round(diff / 60000); if (min < 1) return 'just now'; if (min < 60) return `${min}m ago`; return `${Math.round(min/60)}h ago`; }
function badge(level) { const l = level || 'unknown'; return `<span class="badge" style="background:${COLORS[l] || COLORS.unknown}">${esc(l)}</span>`; }
function prop(feature) { return feature.properties || {}; }
function latOf(feature) { return Number(feature.geometry.coordinates[1]); }
function lonOf(feature) { return Number(feature.geometry.coordinates[0]); }
function showError(msg) { const box = document.getElementById('errorBox'); box.style.display = 'block'; box.innerHTML = `<h3>Map load problem</h3><p>${esc(msg)}</p>`; }
function clearError() { const box = document.getElementById('errorBox'); box.style.display = 'none'; box.innerHTML = ''; }

function incidentPopup(p) {
  return `<strong>Incident #${esc(p.id)}</strong><br>${badge(p.severity_level)} ${esc(p.incident_status || 'new')}<br><br>` +
    `<strong>SOS:</strong> ${esc(p.body)}<br>` +
    `<strong>Accuracy:</strong> ${esc(p.acc ?? '—')} m · ${esc(p.location_quality || 'unknown')}<br>` +
    `<strong>Coordinates:</strong> ${esc(p.map_lat ?? p.lat)}, ${esc(p.map_lon ?? p.lon)}<br>` +
    `<strong>Received:</strong> ${esc(age(p.received_at_ms))}`;
}

function hotspotPopup(h) {
  return `<strong>${esc(h.id)}</strong><br>${badge(h.severity_level)} hotspot<br><br>` +
    `<strong>Incidents:</strong> ${esc(h.event_count)} reports from ${esc(h.unique_senders)} sender(s)<br>` +
    `<strong>Link radius:</strong> ${esc(h.cluster_radius_m || h.radius_m)} m<br>` +
    `<strong>Display radius:</strong> ≈ ${esc(h.radius_m)} m<br>` +
    `<strong>Max pair distance:</strong> ${esc(h.max_pair_distance_m ?? '—')} m<br>` +
    `<strong>Event IDs:</strong> ${esc((h.event_ids || []).join(', '))}`;
}

function showIncident(p) {
  document.getElementById('details').innerHTML = `${incidentPopup(p)}<br><br>` +
    `<strong>Triage:</strong> injury=${esc(p.injury_status || '—')}, mobility=${esc(p.mobility_status || '—')}, hazards=${esc((p.hazard_flags || []).join(', ') || '—')}, people=${esc(p.people_count || '—')}`;
}

function showHotspot(h) {
  document.getElementById('details').innerHTML = `${hotspotPopup(h)}<br><br>` +
    `<strong>Center:</strong> ${esc(Number(h.lat).toFixed(6))}, ${esc(Number(h.lon).toFixed(6))}<br>` +
    `<strong>Score:</strong> ${esc(h.severity_score)}`;
}

function initLeaflet() {
  if (!window.L || leafletMap) return !!leafletMap;
  leafletMap = L.map('map', { zoomControl: true, attributionControl: true }).setView([0, 0], 2);
  tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 20,
    attribution: '&copy; OpenStreetMap contributors'
  }).addTo(leafletMap);
  tileLayer.on('tileload', () => { realMapTilesLoaded = true; });
  tileLayer.on('tileerror', () => fallbackToLocalPlot());
  incidentLayer = L.layerGroup().addTo(leafletMap);
  hotspotLayer = L.layerGroup().addTo(leafletMap);
  return true;
}

function renderLeaflet() {
  if (!initLeaflet()) return false;
  document.getElementById('map').style.display = 'block';
  document.getElementById('fallbackMap').style.display = 'none';
  incidentLayer.clearLayers();
  hotspotLayer.clearLayers();
  const bounds = [];

  for (const h of state.hotspots) {
    const color = COLORS[h.severity_level] || COLORS.unknown;
    const center = [Number(h.lat), Number(h.lon)];
    L.circle(center, { radius: Math.max(25, Number(h.radius_m || 80)), color, fillColor: color, fillOpacity: 0.18, weight: 2 })
      .bindPopup(hotspotPopup(h)).on('click', () => showHotspot(h)).addTo(hotspotLayer);
    bounds.push(center);
  }

  for (const f of state.features) {
    const p = prop(f); const center = [latOf(f), lonOf(f)]; const color = COLORS[p.severity_level] || COLORS.unknown;
    const marker = L.circleMarker(center, { radius: 8, color: '#fff', weight: 2, fillColor: color, fillOpacity: 0.95 })
      .bindPopup(incidentPopup(p)).on('click', () => showIncident(p)).addTo(incidentLayer);
    marker.bindTooltip(`#${p.id}`, { permanent: true, direction: 'right', offset: [8, 0] });
    const acc = Number(p.acc || 0);
    if (acc > 0) L.circle(center, { radius: acc, color: '#222', opacity: 0.35, fillOpacity: 0.03, dashArray: '4 4', weight: 1 }).addTo(incidentLayer);
    bounds.push(center);
  }

  if (bounds.length) leafletMap.fitBounds(bounds, { padding: [40, 40], maxZoom: 18 });
  setTimeout(() => leafletMap.invalidateSize(), 60);
  setTimeout(() => {
    if (!realMapTilesLoaded && state.features.length) fallbackToLocalPlot();
  }, 3500);
  return true;
}

function getBounds(points) {
  if (!points.length) return null;
  let minLat=90,maxLat=-90,minLon=180,maxLon=-180;
  for (const p of points) { minLat=Math.min(minLat,p.lat); maxLat=Math.max(maxLat,p.lat); minLon=Math.min(minLon,p.lon); maxLon=Math.max(maxLon,p.lon); }
  const latPad=Math.max((maxLat-minLat)*0.20,0.0008); const lonPad=Math.max((maxLon-minLon)*0.20,0.0008);
  return {minLat:minLat-latPad,maxLat:maxLat+latPad,minLon:minLon-lonPad,maxLon:maxLon+lonPad};
}
function project(lat, lon, b) { return { x: ((lon-b.minLon)/Math.max(1e-12,b.maxLon-b.minLon))*100, y: (1-((lat-b.minLat)/Math.max(1e-12,b.maxLat-b.minLat)))*100 }; }
function metersToPixels(meters, b) { const el=document.getElementById('fallbackMap'); const mid=(b.minLat+b.maxLat)/2; const across=Math.max(1,(b.maxLon-b.minLon)*111320*Math.cos(mid*Math.PI/180)); return meters/across*el.clientWidth; }

function renderLocalPlot() {
  document.getElementById('map').style.display = 'none';
  const canvas = document.getElementById('fallbackMap');
  canvas.style.display = 'block';
  canvas.innerHTML = '';
  const points = state.features.map(f => ({kind:'incident', lat:latOf(f), lon:lonOf(f), props:prop(f)}))
    .concat(state.hotspots.map(h => ({kind:'hotspot', lat:Number(h.lat), lon:Number(h.lon), props:h})));
  const b = getBounds(points);
  if (!b) return;

  const labels = [
    [`N ${b.maxLat.toFixed(6)}`, 'top:52px;left:50%;transform:translateX(-50%)'],
    [`S ${b.minLat.toFixed(6)}`, 'bottom:52px;left:50%;transform:translateX(-50%)'],
    [`W ${b.minLon.toFixed(6)}`, 'left:18px;top:50%;transform:translateY(-50%)'],
    [`E ${b.maxLon.toFixed(6)}`, 'right:18px;top:50%;transform:translateY(-50%)']
  ];
  for (const [txt, style] of labels) { const el=document.createElement('div'); el.className='axis-label'; el.style.cssText=style; el.textContent=txt; canvas.appendChild(el); }

  for (const p of points.filter(x => x.kind === 'hotspot')) {
    const pos=project(p.lat,p.lon,b); const d=Math.max(54, metersToPixels(Number(p.props.radius_m||80)*2,b)); const el=document.createElement('div');
    el.className='fallback-hotspot'; el.style.left=`${pos.x}%`; el.style.top=`${pos.y}%`; el.style.width=`${d}px`; el.style.height=`${d}px`; el.style.borderColor=COLORS[p.props.severity_level]||COLORS.unknown; el.style.background=`${COLORS[p.props.severity_level]||COLORS.unknown}26`; el.textContent=p.props.event_count; el.onclick=()=>showHotspot(p.props); canvas.appendChild(el);
  }
  for (const p of points.filter(x => x.kind === 'incident')) {
    const pos=project(p.lat,p.lon,b); const acc=Number(p.props.acc||0);
    if (acc>0) { const ring=document.createElement('div'); const d=Math.min(300,Math.max(18,metersToPixels(acc*2,b))); ring.className='fallback-ring'; ring.style.left=`${pos.x}%`; ring.style.top=`${pos.y}%`; ring.style.width=`${d}px`; ring.style.height=`${d}px`; canvas.appendChild(ring); }
    const el=document.createElement('div'); el.className='fallback-marker'; el.dataset.id=`#${p.props.id}`; el.style.left=`${pos.x}%`; el.style.top=`${pos.y}%`; el.style.background=COLORS[p.props.severity_level]||COLORS.unknown; el.onclick=()=>showIncident(p.props); canvas.appendChild(el);
  }
}

function renderMap() {
  document.getElementById('empty').style.display = state.features.length ? 'none' : 'block';
  if (!state.features.length) {
    document.getElementById('scale').textContent = 'Scale: —';
  } else {
    const lats = state.features.map(latOf); const lons = state.features.map(lonOf);
    const mid = (Math.min(...lats) + Math.max(...lats)) / 2;
    const widthM = Math.max(1, (Math.max(...lons)-Math.min(...lons)) * 111320 * Math.cos(mid*Math.PI/180));
    const heightM = Math.max(1, (Math.max(...lats)-Math.min(...lats)) * 111320);
    document.getElementById('scale').textContent = `Incident spread ≈ ${Math.round(widthM)} m E/W · ${Math.round(heightM)} m N/S`;
  }
  if (window.L) {
    const ok = renderLeaflet();
    if (ok) return;
  }
  renderLocalPlot();
}

function fallbackToLocalPlot() {
  if (tileFailureFallbackStarted) return;
  tileFailureFallbackStarted = true;
  renderLocalPlot();
}

function renderLists() {
  const hotspotList = document.getElementById('hotspotList');
  hotspotList.innerHTML = state.hotspots.length ? state.hotspots.slice(0,8).map((h,idx)=>
    `<div class="item hotspot-item" data-idx="${idx}"><strong>${badge(h.severity_level)} ${esc(h.id)}</strong><div class="meta">${esc(h.event_count)} incidents · link radius ${esc(h.cluster_radius_m || h.radius_m)} m · display radius ≈ ${esc(h.radius_m)} m · newest ${esc(age(h.newest_received_at_ms))}<br>IDs: ${esc((h.event_ids || []).join(', '))}</div></div>`).join('')
    : '<div class="item"><div class="meta">No hotspot clusters in the selected window.</div></div>';
  hotspotList.querySelectorAll('.hotspot-item').forEach(el => el.addEventListener('click', () => showHotspot(state.hotspots[Number(el.dataset.idx)])));

  const incidentList = document.getElementById('incidentList');
  const incs = state.features.map(prop).slice(0,12);
  incidentList.innerHTML = incs.length ? incs.map((p,idx)=>
    `<div class="item incident-item" data-idx="${idx}"><strong>${badge(p.severity_level)} Incident #${esc(p.id)}</strong><div class="meta">${esc(p.location_quality || 'unknown')} · ${esc(age(p.received_at_ms))}<br>${esc(p.body || '')}</div></div>`).join('')
    : '<div class="item"><div class="meta">No incidents in the selected window.</div></div>';
  incidentList.querySelectorAll('.incident-item').forEach(el => el.addEventListener('click', () => showIncident(incs[Number(el.dataset.idx)])));
}

async function fetchJson(url) {
  const resp = await fetch(url, { cache: 'no-store' });
  if (!resp.ok) throw new Error(`${url} returned HTTP ${resp.status}`);
  return await resp.json();
}

async function loadData() {
  clearError();
  const w = document.getElementById('window').value || 60;
  const grid = document.getElementById('grid').value || 50;
  const minEvents = document.getElementById('minEvents').value || 2;
  const [incidents, hotspotsResp, summary] = await Promise.all([
    fetchJson(`/geo/incidents?window_minutes=${encodeURIComponent(w)}&limit=2000`),
    fetchJson(`/geo/hotspots?window_minutes=${encodeURIComponent(w)}&radius_m=${encodeURIComponent(grid)}&min_events=${encodeURIComponent(minEvents)}&limit=2000`),
    fetchJson(`/geo/summary?window_minutes=${encodeURIComponent(w)}&limit=2000`)
  ]);
  state.features = incidents.features || [];
  state.hotspots = hotspotsResp.hotspots || [];
  state.summary = summary || {};
  tileFailureFallbackStarted = false;
  document.getElementById('mappedCount').textContent = state.summary.mapped_event_count ?? state.features.length;
  document.getElementById('hotspotCount').textContent = state.hotspots.length;
  document.getElementById('status').textContent = `Last refresh ${new Date().toLocaleTimeString()} · ${state.features.length} reports in selected window`;
  renderMap(); renderLists();
}


loadData().catch(err => showError(String(err)));
setInterval(() => loadData().catch(err => console.error(err)), 5000);
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

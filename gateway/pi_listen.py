import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any, Set

from bleak import BleakScanner, BleakClient
from bleak.exc import BleakDBusError

from bitchat_protocol import (
    decode_packet,
    hex_peer_id_to_bytes,
    MESSAGE_TYPE_NOISE_ENCRYPTED,
    MESSAGE_TYPE_NOISE_HANDSHAKE,
)
from bitchat_pm import BitChatPrivateMessenger
from gateway_store import GatewayStore
from copilot_engine import CopilotEngine

# ============================================================
# BitChat UUIDs
# ============================================================
SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHAR_UUID    = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
SERVICE_UUID_NORM = SERVICE_UUID.lower()

# ============================================================
# Gateway behavior
# ============================================================
MIN_CONNECTED = 2
MAX_DEVICES   = 6

# Scanning / manager
ACQUIRE_TICK_S        = 2
MAINTAIN_TICK_S       = 10
DISCOVERY_FRESH_S     = 40
DISCOVERY_RETENTION_S = 60

# Ignore obviously bad/stale RSSI candidates
MIN_CONNECT_RSSI      = -100

# Connection / recovery
CONNECT_RETRIES            = 6
CONNECT_ATTEMPT_TIMEOUT_S  = 10
CONNECT_FAIL_BACKOFF_S     = 20
CONNECTING_STALE_S         = 25
# For established listening sessions, treat either BLE advertisements
# or received GATT notifications as proof that the link is still useful.
# This must be longer than CONNECTING_STALE_S so connected peers are
# not dropped just because scanning was paused/missed during radio ops.
LINK_IDLE_DROP_S           = 60
WATCHDOG_EVERY_S           = 2

# Dedup
DEDUP_TTL_S = 90
DEDUP_MAX   = 5000

# ============================================================
# Locks / events
# ============================================================
SCANNER_LOCK = asyncio.Lock()
RADIO_LOCK   = asyncio.Lock()
CONNECT_LOCK = asyncio.Lock()

MANAGER_WAKE = asyncio.Event()

# ============================================================
# Runtime state
# ============================================================
DEDUP: Dict[str, float] = {}
BACKOFF_UNTIL: Dict[str, float] = {}

# address -> Discovery
DISCOVERED: Dict[str, "Discovery"] = {}

# address -> Session
SESSIONS: Dict[str, "Session"] = {}

SCANNER: Optional[BleakScanner] = None
SCANNER_RUNNING = False

LAST_STATE_LINE = ""

# Storing in the database
DB_PATH = "sos_gateway.db"
STORE: Optional[GatewayStore] = None
ENGINE: Optional[CopilotEngine] = None

# Private-message transport for Pi -> BitChat Safety Copilot communication
PM = BitChatPrivateMessenger(CHAR_UUID)
PM_TARGET_BYTES = hex_peer_id_to_bytes(PM.my_peer_id())
PENDING_PM: Dict[str, List[str]] = {}
PM_DEDUP_TTL_S = 120
PM_SEEN: Dict[str, float] = {}



@dataclass
class Discovery:
    address: str
    dev: Any
    adv: Any
    rssi: int
    last_seen: float
    name: str = ""


@dataclass
class Session:
    address: str
    dev: Any
    adv: Any
    rssi: int

    state: str = "new"   # new | connecting | listening | stopping
    client: Optional[BleakClient] = None
    task: Optional[asyncio.Task] = None
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)

    ever_connected: bool = False

    started_at: float = field(default_factory=time.time)
    connected_at: float = 0.0
    last_adv_seen: float = 0.0
    last_packet_at: float = 0.0
    packet_count: int = 0
    disconnect_reason: Optional[str] = None

    # Debug only: mesh peers observed through this BLE link
    seen_peer_ids: Set[str] = field(default_factory=set)
    
    
def _now() -> float:
    return time.time()


def _norm_uuid(u: str) -> str:
    return (u or "").strip().lower()


def connected_count() -> int:
    return sum(1 for s in SESSIONS.values() if s.state == "listening")


def occupied_slots() -> int:
    return sum(1 for s in SESSIONS.values() if s.state in ("connecting", "listening", "stopping"))


def current_mode() -> str:
    if connected_count() < MIN_CONNECTED and occupied_slots() < MAX_DEVICES:
        return "acquire"
    return "maintain"


def session_last_activity(sess: "Session") -> float:
    """Return the newest activity timestamp for a listening BLE session.

    BLE advertisements are useful for discovery, but an established GATT
    notification stream is stronger proof that the link is still alive.
    Therefore, a connected session is considered active if either an
    advertisement OR a packet/notification was seen recently.
    """
    return max(
        sess.last_adv_seen or 0.0,
        sess.last_packet_at or 0.0,
        sess.connected_at or 0.0,
    )


def _age_text(now: float, ts: float) -> str:
    if not ts:
        return "never"
    return f"{int(now - ts)}s"


def log_state(force: bool = False) -> None:
    global LAST_STATE_LINE
    line = f"[STATE] connected={connected_count()} occupied={occupied_slots()}/{MAX_DEVICES} mode={current_mode()} discovered={len(DISCOVERED)}"
    if force or line != LAST_STATE_LINE:
        print(line)
        LAST_STATE_LINE = line


def _extract_sos(payload_bytes: bytes) -> Optional[dict]:
    try:
        s = payload_bytes.decode("utf-8", errors="strict")
        obj = json.loads(s)
        return obj if obj.get("type") == "SOS" else None
    except Exception:
        return None


def _dedup_key(sender_peer_hex: str, sos: dict) -> str:
    return f"{sender_peer_hex}|{sos.get('time')}|{sos.get('body', '')}"


def _dedup_accept(key: str) -> bool:
    now = _now()

    if len(DEDUP) > DEDUP_MAX:
        for k, exp in list(DEDUP.items()):
            if exp < now:
                DEDUP.pop(k, None)

    exp = DEDUP.get(key)
    if exp and exp > now:
        return False

    DEDUP[key] = now + DEDUP_TTL_S
    return True


def _pm_accept(kind: str, sender_peer_hex: str, message_id: str) -> bool:
    now = _now()
    if len(PM_SEEN) > DEDUP_MAX:
        for k, exp in list(PM_SEEN.items()):
            if exp < now:
                PM_SEEN.pop(k, None)
    key = f"{kind}|{sender_peer_hex}|{message_id}"
    exp = PM_SEEN.get(key)
    if exp and exp > now:
        return False
    PM_SEEN[key] = now + PM_DEDUP_TTL_S
    return True


async def queue_or_send_private_message(sess: "Session", recipient_peer_hex: str, content: str) -> None:
    client = sess.client
    if client is None or not client.is_connected:
        print(f"[PM] cannot send to {recipient_peer_hex}: BLE client not connected")
        return

    try:
        session = PM._session_for(recipient_peer_hex)
        if session.established:
            await PM.send_private_message(client, recipient_peer_hex, content)
            return

        pending = PENDING_PM.setdefault(recipient_peer_hex, [])
        pending.append(content)
        await PM.ensure_noise_session(client, recipient_peer_hex)
    except Exception as e:
        print(f"[PM] failed to queue/send to {recipient_peer_hex}: {e}")


async def flush_pending_private_messages(sess: "Session", recipient_peer_hex: str) -> None:
    client = sess.client
    if client is None or not client.is_connected:
        return
    queued = PENDING_PM.pop(recipient_peer_hex, [])
    for content in queued:
        try:
            await asyncio.sleep(0.15)
            await PM.send_private_message(client, recipient_peer_hex, content)
        except Exception as e:
            print(f"[PM] failed while flushing queued message to {recipient_peer_hex}: {e}")
            
            
def build_copilot_reply(victim_text: str) -> str:
    """Bounded, rules-first Safety Copilot v1."""
    text = (victim_text or "").strip().lower()

    if "severe" in text or "critical" in text or "bleed" in text or "blood" in text:
        return (
            "Safety Copilot: I marked your injury as SEVERE. "
            "If it is safe, apply firm pressure to bleeding, stay low if there is smoke, "
            "and reply: trapped / mobile / unsure."
        )

    if "mild" in text:
        return (
            "Safety Copilot: I marked your injury as MILD. "
            "Are you trapped, mobile, or unsure? Reply with one word: trapped / mobile / unsure."
        )

    if text in ("none", "no") or "not injured" in text or "no injury" in text:
        return (
            "Safety Copilot: I marked injury as NONE. "
            "Are you trapped, mobile, or unsure? Reply with one word: trapped / mobile / unsure."
        )

    if "trapped" in text:
        return (
            "Safety Copilot: I marked you as TRAPPED. Stay where you are if moving is unsafe. "
            "Reply with hazards you see: fire / smoke / collapse / flood / none."
        )

    if "mobile" in text:
        return (
            "Safety Copilot: I marked you as MOBILE. If safe, move away from danger and stay visible. "
            "Reply with hazards: fire / smoke / collapse / flood / none."
        )

    if "unsure" in text:
        return (
            "Safety Copilot: I marked mobility as UNSURE. Do not move if you suspect injury or collapse risk. "
            "Reply with hazards: fire / smoke / collapse / flood / none."
        )

    if any(word in text for word in ["fire", "smoke", "collapse", "flood"]):
        return (
            "Safety Copilot: Hazard noted. Stay low around smoke, avoid unstable areas, "
            "and conserve battery. Responders will see this incident update."
        )

    return (
        "Safety Copilot: I received your reply. Please answer with one of these words so I can triage: "
        "none / mild / severe / trapped / mobile / unsure / fire / smoke / collapse / flood."
    )


def prune_discovery_cache(now: float) -> None:
    for addr, rec in list(DISCOVERED.items()):
        if now - rec.last_seen > DISCOVERY_RETENTION_S:
            DISCOVERED.pop(addr, None)


def fresh_discoveries(now: float) -> List[Discovery]:
    items = [rec for rec in DISCOVERED.values() if now - rec.last_seen <= DISCOVERY_FRESH_S]
    items.sort(key=lambda x: x.rssi, reverse=True)
    return items


async def request_session_stop(sess: Session, reason: str) -> None:
    if sess.state in ("connecting", "listening") and not sess.stop_event.is_set():
        sess.state = "stopping"
        sess.disconnect_reason = reason
        print(f"[{sess.address}] stopping session: {reason}")
        sess.stop_event.set()
        MANAGER_WAKE.set()


def _session_done_callback(addr: str):
    def _cb(task: asyncio.Task):
        SESSIONS.pop(addr, None)

        try:
            exc = task.exception()
            if exc:
                print(f"[{addr}] session task ended with error: {exc}")
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

        MANAGER_WAKE.set()
        log_state(force=True)

    return _cb
    
    
# ============================================================
# Scanner control
# ============================================================
def scanner_callback(dev, adv) -> None:
    uuids = getattr(adv, "service_uuids", None) or []
    uuids_norm = [_norm_uuid(u) for u in uuids]
    if SERVICE_UUID_NORM not in uuids_norm:
        return

    now = _now()

    rssi = getattr(adv, "rssi", None)
    if rssi is None:
        rssi = getattr(dev, "rssi", -999)
    try:
        rssi = int(rssi)
    except Exception:
        rssi = -999

    DISCOVERED[dev.address] = Discovery(
        address=dev.address,
        dev=dev,
        adv=adv,
        rssi=rssi,
        last_seen=now,
        name=dev.name or "",
    )

    sess = SESSIONS.get(dev.address)
    if sess:
        sess.dev = dev
        sess.adv = adv
        sess.rssi = rssi
        sess.last_adv_seen = now
    else:
        MANAGER_WAKE.set()


async def ensure_scanner_started() -> None:
    global SCANNER, SCANNER_RUNNING

    async with SCANNER_LOCK:
        if SCANNER is None:
            SCANNER = BleakScanner(
                detection_callback=scanner_callback,
                service_uuids=[SERVICE_UUID],
            )

        if not SCANNER_RUNNING:
            async with RADIO_LOCK:
                await SCANNER.start()
            SCANNER_RUNNING = True


async def ensure_scanner_stopped() -> None:
    global SCANNER_RUNNING

    async with SCANNER_LOCK:
        if SCANNER is not None and SCANNER_RUNNING:
            async with RADIO_LOCK:
                try:
                    await SCANNER.stop()
                except Exception:
                    pass
            SCANNER_RUNNING = False


async def run_radio_op_with_scanner_paused(coro_factory, timeout: Optional[float] = None):
    async with CONNECT_LOCK:
        await ensure_scanner_stopped()
        try:
            async with RADIO_LOCK:
                coro = coro_factory()
                if timeout is not None:
                    return await asyncio.wait_for(coro, timeout=timeout)
                return await coro
        finally:
            await ensure_scanner_started()
            
            
# ============================================================
# BLE session handling
# ============================================================
async def connect_with_retry(client: BleakClient, label: str, sess: Session, attempts: int = CONNECT_RETRIES) -> bool:
    for attempt in range(1, attempts + 1):
        if sess.stop_event.is_set():
            return False

        try:
            await run_radio_op_with_scanner_paused(
                lambda: client.connect(),
                timeout=CONNECT_ATTEMPT_TIMEOUT_S,
            )
            return True

        except asyncio.TimeoutError:
            print(f"[{label}] connect attempt {attempt}/{attempts} timed out")
            try:
                async with RADIO_LOCK:
                    if client.is_connected:
                        await asyncio.wait_for(client.disconnect(), timeout=5)
            except Exception:
                pass
            await asyncio.sleep(0.7 * attempt)

        except BleakDBusError as e:
            msg = str(e)
            if "InProgress" in msg or "Operation already in progress" in msg:
                print(f"[{label}] connect attempt {attempt}/{attempts} -> InProgress, retrying...")
            else:
                print(f"[{label}] connect attempt {attempt}/{attempts} failed (DBus): {e}")

            try:
                async with RADIO_LOCK:
                    if client.is_connected:
                        await asyncio.wait_for(client.disconnect(), timeout=5)
            except Exception:
                pass
            await asyncio.sleep(0.7 * attempt)

        except Exception as e:
            print(f"[{label}] connect attempt {attempt}/{attempts} failed: {e}")
            try:
                async with RADIO_LOCK:
                    if client.is_connected:
                        await asyncio.wait_for(client.disconnect(), timeout=5)
            except Exception:
                pass
            await asyncio.sleep(0.7 * attempt)

    return False


async def safe_disconnect(client: Optional[BleakClient]) -> None:
    if client is None:
        return

    try:
        async with RADIO_LOCK:
            if client.is_connected:
                await asyncio.wait_for(client.disconnect(), timeout=5)
    except Exception:
        pass


async def safe_stop_notify(client: Optional[BleakClient]) -> None:
    if client is None:
        return

    try:
        async with RADIO_LOCK:
            if client.is_connected:
                try:
                    await asyncio.wait_for(client.stop_notify(CHAR_UUID), timeout=5)
                except Exception:
                    pass
    except Exception:
        pass
        

# Storing SoS messages
def save_accepted_sos(sess: Session, pkt, sos: dict, dedup_key: str) -> tuple[bool, int]:
    global STORE
    if STORE is None:
        return False, -1

    return STORE.insert_sos_event(
        sender_peer=pkt.sender_peer_hex,
        via_ble=sess.address,
        ttl_seen=pkt.ttl,
        sos=sos,
        dedup_key=dedup_key,
    )
    
    
async def connect_and_listen(sess: Session) -> None:
    address = sess.address
    label = f"{address} (rssi={sess.rssi})"
    disconnected = asyncio.Event()

    def on_disconnect(_client):
        # Ignore callback spam before a real successful connect
        if not sess.ever_connected:
            return

        if not disconnected.is_set():
            print(f"[{label}] disconnected")
            disconnected.set()
            MANAGER_WAKE.set()

    client = BleakClient(address, disconnected_callback=on_disconnect)
    sess.client = client
    sess.state = "connecting"

    try:
        print(f"[{label}] connecting...")
        ok = await connect_with_retry(client, label, sess)
        if not ok:
            BACKOFF_UNTIL[address] = _now() + CONNECT_FAIL_BACKOFF_S
            print(f"[{label}] giving up for now; backoff {CONNECT_FAIL_BACKOFF_S}s")
            return

        sess.ever_connected = True
        sess.state = "listening"
        sess.connected_at = _now()
        sess.packet_count = 0
        sess.last_adv_seen = _now()

        mtu = getattr(client, "mtu_size", None)
        print(f"[{label}] connected (mtu={mtu if mtu is not None else 'unknown'})")
        
        def handle_notify(_sender, data: bytearray):
            raw = bytes(data)

            # Any notification from this GATT characteristic is link activity.
            # Update this before decoding so malformed/unsupported packets do
            # not make an otherwise alive BLE session look idle to the watchdog.
            sess.last_packet_at = _now()

            # A) raw notification visibility
            print(f"[NOTIFY] via={sess.address} bytes={len(raw)}")
            print(f"[NOTIFY] hex={raw[:32].hex()}")

            pkt = decode_packet(raw)
            if pkt is None:
                print("[DECODE] failed")
                return

            # keep your existing decoded-packet tracking
            sess.packet_count += 1
            sess.seen_peer_ids.add(pkt.sender_peer_hex)

            # B) decode visibility
            print(
                f"[DECODE] ok "
                f"version={pkt.version} type={pkt.type} ttl={pkt.ttl} "
                f"sender={pkt.sender_peer_hex} payload_len={len(pkt.payload)}"
            )

            # C) payload visibility
            try:
                preview = pkt.payload.decode("utf-8", errors="strict")
                print(f"[PAYLOAD] utf8={preview[:120]}")
            except Exception:
                print("[PAYLOAD] non-utf8 or decode failed")

            # C.1) Handle private-message Noise handshake replies addressed to the Pi gateway
            if pkt.type == MESSAGE_TYPE_NOISE_HANDSHAKE and pkt.recipient_id == PM_TARGET_BYTES:
                async def _handle_handshake():
                    try:
                        established = await PM.process_handshake_packet(client, pkt.sender_peer_hex, pkt.payload)
                        if established:
                            await flush_pending_private_messages(sess, pkt.sender_peer_hex)
                    except Exception as e:
                        print(f"[PM] handshake processing failed from {pkt.sender_peer_hex}: {e}")

                asyncio.create_task(_handle_handshake())
                return

            # C.2) Handle inbound encrypted private messages / receipts addressed to the Pi gateway
            if pkt.type == MESSAGE_TYPE_NOISE_ENCRYPTED and pkt.recipient_id == PM_TARGET_BYTES:
                try:
                    pm = PM.decrypt_private_message(pkt.sender_peer_hex, pkt.payload)
                    pm_type = pm.get("type")
                    pm_id = str(pm.get("message_id") or "")

                    if pm_type == "private_message":
                        if pm_id and not _pm_accept("private_message", pkt.sender_peer_hex, pm_id):
                            print(f"[PM] duplicate private reply suppressed from={pkt.sender_peer_hex} msg_id={pm_id[:8]}...")
                            return
                        content = pm.get("content", "")
                        print(f"[PM] inbound private reply from={pkt.sender_peer_hex} msg_id={pm_id[:8]}... content={content}")

                        async def _reply_to_victim():
                            try:
                                await PM.send_delivery_ack(client, pkt.sender_peer_hex, pm_id)
                                replies = ENGINE.handle_reply(pkt.sender_peer_hex, content) if ENGINE is not None else []
                                for reply in replies:
                                    await queue_or_send_private_message(sess, pkt.sender_peer_hex, reply)
                            except Exception as e:
                                print(f"[COPILOT] failed to reply to {pkt.sender_peer_hex}: {type(e).__name__}: {e!r}")

                        asyncio.create_task(_reply_to_victim())

                    elif pm_type == "delivered":
                        if pm_id and not _pm_accept("delivered", pkt.sender_peer_hex, pm_id):
                            return
                        print(f"[PM] delivery ACK from={pkt.sender_peer_hex} for msg_id={pm_id[:8]}...")

                    elif pm_type == "read_receipt":
                        if pm_id and not _pm_accept("read_receipt", pkt.sender_peer_hex, pm_id):
                            return
                        print(f"[PM] read receipt from={pkt.sender_peer_hex} for msg_id={pm_id[:8]}...")

                    else:
                        print(f"[PM] inbound Noise payload from={pkt.sender_peer_hex}: {pm}")

                except Exception as e:
                    print(f"[PM] failed to decrypt inbound private Noise payload from {pkt.sender_peer_hex}: {type(e).__name__}: {e!r}")
                return
                
            # D) SOS parse visibility
            sos = _extract_sos(pkt.payload)
            if sos is None:
                print("[SOS] payload is not SOS JSON")
                return

            print("[SOS] matched")
            
            # added print to know that SoS was stored in RAM
            key = _dedup_key(pkt.sender_peer_hex, sos)
            if not _dedup_accept(key):
                print("[STORE] duplicate suppressed in RAM dedup")
                return

            stored, event_id = save_accepted_sos(sess, pkt, sos, key)

            body = sos.get("body", "")
            lat = sos.get("lat")
            lon = sos.get("lon")
            acc = sos.get("acc")
            t = sos.get("time")

            print("\n=== SOS RECEIVED ===")
            print(f"event_id={event_id} from_peer={pkt.sender_peer_hex} via_ble={sess.address} ttl={pkt.ttl} time={t}")
            print(f"body: {body}")
            if lat is not None and lon is not None:
                print(f"loc: {lat}, {lon} acc={acc}")
            if STORE is not None and event_id > 0:
                stored_event = STORE.get_event(event_id)
                if stored_event:
                    print(
                        "geo: "
                        f"status={stored_event.get('coord_status')} "
                        f"quality={stored_event.get('location_quality')} "
                        f"cell={stored_event.get('geocell') or 'none'}"
                    )
            print(f"stored_to_db={stored}")
            print("====================\n")

            async def _start_copilot():
                try:
                    print(f"[PM] starting copilot workflow to {pkt.sender_peer_hex} for event={event_id}")
                    replies = ENGINE.start_for_event(event_id) if ENGINE is not None else []
                    for reply in replies:
                        await queue_or_send_private_message(sess, pkt.sender_peer_hex, reply)
                except Exception as e:
                    print(f"[PM] failed to start copilot for {pkt.sender_peer_hex}: {type(e).__name__}: {e!r}")

            asyncio.create_task(_start_copilot())
            # The end of the modified part

        print(f"[{label}] subscribing to notifications on {CHAR_UUID} ...")
        await run_radio_op_with_scanner_paused(
            lambda: client.start_notify(CHAR_UUID, handle_notify),
            timeout=8,
        )
        print(f"[{label}] listening...")

        # Tell Android that the Pi is a named gateway peer.
        try:
            await PM.send_announce(client, nickname="Safety Copilot Gateway")
        except Exception as e:
            print(f"[PM] failed to send gateway announce: {type(e).__name__}: {e!r}")

        stop_task = asyncio.create_task(sess.stop_event.wait())
        disc_task = asyncio.create_task(disconnected.wait())

        done, pending = await asyncio.wait(
            {stop_task, disc_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for p in pending:
            p.cancel()

    except Exception as e:
        print(f"[{label}] error: {e}")

    finally:
        await safe_stop_notify(client)
        await safe_disconnect(client)


async def start_session(rec: Discovery) -> None:
    addr = rec.address
    now = _now()

    if addr in SESSIONS:
        return

    if BACKOFF_UNTIL.get(addr, 0) > now:
        return

    sess = Session(
        address=addr,
        dev=rec.dev,
        adv=rec.adv,
        rssi=rec.rssi,
        last_adv_seen=rec.last_seen,
    )

    task = asyncio.create_task(connect_and_listen(sess))
    sess.task = task
    SESSIONS[addr] = sess
    task.add_done_callback(_session_done_callback(addr))
    
    
# ============================================================
# Manager / watchdog
# ============================================================
async def run_manager_cycle() -> None:
    now = _now()
    prune_discovery_cache(now)

    mode = current_mode()
    target_slots = min(MAX_DEVICES, MIN_CONNECTED) if mode == "acquire" else MAX_DEVICES

    candidates: List[Discovery] = []
    for rec in fresh_discoveries(now):
        if rec.address in SESSIONS:
            continue
        if BACKOFF_UNTIL.get(rec.address, 0) > now:
            continue
        if rec.rssi <= MIN_CONNECT_RSSI:
            continue
        candidates.append(rec)

    if candidates:
        pretty = ", ".join(f"{c.address}@{c.rssi}" for c in candidates[:8])
        print(f"[MANAGER] fresh candidates: {pretty}")

    for rec in candidates:
        if occupied_slots() >= target_slots:
            break
        await start_session(rec)

    log_state()


async def watchdog_loop() -> None:
    while True:
        await asyncio.sleep(WATCHDOG_EVERY_S)
        now = _now()

        for sess in list(SESSIONS.values()):
            if sess.state == "connecting":
                if now - sess.started_at > CONNECTING_STALE_S:
                    await request_session_stop(sess, f"connect timeout > {CONNECTING_STALE_S}s")
                continue

            if sess.state != "listening":
                continue

            client = sess.client

            try:
                if client is not None and not client.is_connected:
                    await request_session_stop(sess, "bleak reports disconnected")
                    continue
            except Exception:
                pass

            # Do not drop a connected/listening session only because
            # advertisements were missed. Scanner pauses, Android BLE privacy
            # rotation, or BlueZ discovery gaps can hide advertisements while
            # the GATT notification link is still receiving BitChat packets.
            last_activity = session_last_activity(sess)
            idle_age = now - last_activity if last_activity else 999999

            if idle_age > LINK_IDLE_DROP_S:
                await request_session_stop(
                    sess,
                    (
                        f"BitChat link inactive for {int(idle_age)}s "
                        f"(last_adv={_age_text(now, sess.last_adv_seen)}, "
                        f"last_packet={_age_text(now, sess.last_packet_at)})"
                    ),
                )


async def manager_loop() -> None:
    first = True

    while True:
        timeout = ACQUIRE_TICK_S if current_mode() == "acquire" else MAINTAIN_TICK_S

        if first:
            first = False
        else:
            try:
                await asyncio.wait_for(MANAGER_WAKE.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass

        MANAGER_WAKE.clear()
        await run_manager_cycle()
        
        
async def main():
    
    global STORE, ENGINE
    STORE = GatewayStore(DB_PATH)
    ENGINE = CopilotEngine(STORE)
    
    print("Starting BitChat Pi Gateway (mesh-correct session mode)")
    print(f"- Service UUID:               {SERVICE_UUID}")
    print(f"- Char UUID:                  {CHAR_UUID}")
    print(f"- Min connected:              {MIN_CONNECTED}")
    print(f"- Max devices:                {MAX_DEVICES}")
    print(f"- Acquire tick:               {ACQUIRE_TICK_S}s")
    print(f"- Maintain tick:              {MAINTAIN_TICK_S}s")
    print(f"- Discovery fresh window:     {DISCOVERY_FRESH_S}s")
    print(f"- Link idle drop threshold:   {LINK_IDLE_DROP_S}s")
    print(f"- Connect timeout:            {CONNECTING_STALE_S}s")
    print(f"- Connect fail backoff:       {CONNECT_FAIL_BACKOFF_S}s")
    print(f"- Min connect RSSI:           {MIN_CONNECT_RSSI}")
    print(f"- Dedup TTL:                  {DEDUP_TTL_S}s")
    print("")

    await ensure_scanner_started()
    MANAGER_WAKE.set()

    await asyncio.gather(
        manager_loop(),
        watchdog_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())
    

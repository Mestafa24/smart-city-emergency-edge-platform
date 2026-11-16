import struct
import zlib
from dataclasses import dataclass
from typing import Optional

# BinaryProtocol flags (from Android repo)
HAS_RECIPIENT = 0x01
HAS_SIGNATURE = 0x02
IS_COMPRESSED = 0x04

HEADER_SIZE_V1 = 13
HEADER_SIZE_V2 = 15
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > len(data):
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]

def _decompress_deflate(raw_deflate: bytes, original_size: int) -> bytes:
    # Android uses raw deflate (no zlib headers). Python zlib: wbits=-15
    try:
        out = zlib.decompress(raw_deflate, -zlib.MAX_WBITS)
        return out
    except Exception:
        # Fallback: try with zlib headers
        return zlib.decompress(raw_deflate)

@dataclass
class BitchatPacket:
    version: int
    type: int
    ttl: int
    timestamp: int
    sender_id: bytes
    recipient_id: Optional[bytes]
    payload: bytes
    signature: Optional[bytes]

    @property
    def sender_peer_hex(self) -> str:
        return "".join(f"{b:02x}" for b in self.sender_id)

def decode_packet(data: bytes) -> Optional[BitchatPacket]:
    # Try as-is first (Android does this)
    pkt = _decode_core(data)
    if pkt is not None:
        return pkt
    # Try unpadded
    unpadded = pkcs7_unpad(data)
    if unpadded == data:
        return None
    return _decode_core(unpadded)

def _decode_core(raw: bytes) -> Optional[BitchatPacket]:
    try:
        if len(raw) < HEADER_SIZE_V1 + SENDER_ID_SIZE:
            return None

        version = raw[0]
        if version not in (1, 2):
            return None

        header_size = HEADER_SIZE_V1 if version == 1 else HEADER_SIZE_V2

        # version(1), type(1), ttl(1), timestamp(8), flags(1) => 12 bytes so far
        msg_type = raw[1]
        ttl = raw[2]
        timestamp = struct.unpack_from(">Q", raw, 3)[0]
        flags = raw[11]

        has_recipient = (flags & HAS_RECIPIENT) != 0
        has_signature = (flags & HAS_SIGNATURE) != 0
        is_compressed = (flags & IS_COMPRESSED) != 0

        offset = 12
        if version >= 2:
            payload_len = struct.unpack_from(">I", raw, offset)[0]
            offset += 4
        else:
            payload_len = struct.unpack_from(">H", raw, offset)[0]
            offset += 2

        expected = offset + SENDER_ID_SIZE + payload_len
        if has_recipient:
            expected += RECIPIENT_ID_SIZE
        if has_signature:
            expected += SIGNATURE_SIZE
        if len(raw) < expected:
            return None

        sender_id = raw[offset:offset + SENDER_ID_SIZE]
        offset += SENDER_ID_SIZE

        recipient_id = None
        if has_recipient:
            recipient_id = raw[offset:offset + RECIPIENT_ID_SIZE]
            offset += RECIPIENT_ID_SIZE

        if is_compressed:
            if payload_len < 2:
                return None
            original_size = struct.unpack_from(">H", raw, offset)[0]
            offset += 2
            comp = raw[offset:offset + (payload_len - 2)]
            offset += (payload_len - 2)
            payload = _decompress_deflate(comp, original_size)
        else:
            payload = raw[offset:offset + payload_len]
            offset += payload_len

        signature = None
        if has_signature:
            signature = raw[offset:offset + SIGNATURE_SIZE]

        return BitchatPacket(
            version=version,
            type=msg_type,
            ttl=ttl,
            timestamp=timestamp,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            signature=signature,
        )
    except Exception:
        return None

# ------------------------------------------------------------
# Outbound helpers added for Pi -> BitChat private messaging
# ------------------------------------------------------------
MESSAGE_TYPE_ANNOUNCE = 0x01
MESSAGE_TYPE_MESSAGE = 0x02
MESSAGE_TYPE_LEAVE = 0x03
MESSAGE_TYPE_NOISE_HANDSHAKE = 0x10
MESSAGE_TYPE_NOISE_ENCRYPTED = 0x11
MESSAGE_TYPE_FRAGMENT = 0x20
MESSAGE_TYPE_REQUEST_SYNC = 0x21
MESSAGE_TYPE_FILE_TRANSFER = 0x22

BLOCK_SIZES = (256, 512, 1024, 2048)
SYNC_TTL_HOPS = 0

def pkcs7_pad(data: bytes, target_size: int) -> bytes:
    if len(data) >= target_size:
        return data
    padding_needed = target_size - len(data)
    if padding_needed <= 0 or padding_needed > 255:
        return data
    return data + bytes([padding_needed]) * padding_needed

def optimal_block_size(data_size: int) -> int:
    total_size = data_size + 16
    for block_size in BLOCK_SIZES:
        if total_size <= block_size:
            return block_size
    return data_size

def hex_peer_id_to_bytes(peer_hex: str) -> bytes:
    peer_hex = (peer_hex or '').strip().lower()
    out = bytearray(8)
    index = 0
    while len(peer_hex) >= 2 and index < 8:
        out[index] = int(peer_hex[:2], 16)
        peer_hex = peer_hex[2:]
        index += 1
    return bytes(out)

def encode_packet(packet: BitchatPacket, apply_padding: bool = False) -> bytes:
    has_recipient = packet.recipient_id is not None
    has_signature = packet.signature is not None
    flags = 0
    if has_recipient:
        flags |= HAS_RECIPIENT
    if has_signature:
        flags |= HAS_SIGNATURE

    payload = packet.payload
    header = bytearray()
    header.append(packet.version & 0xFF)
    header.append(packet.type & 0xFF)
    header.append(packet.ttl & 0xFF)
    header.extend(struct.pack('>Q', packet.timestamp))
    header.append(flags & 0xFF)
    if packet.version >= 2:
        header.extend(struct.pack('>I', len(payload)))
    else:
        if len(payload) > 0xFFFF:
            raise ValueError('v1 BitChat packet payload is too large')
        header.extend(struct.pack('>H', len(payload)))

    frame = bytearray(header)
    sender = packet.sender_id[:SENDER_ID_SIZE].ljust(SENDER_ID_SIZE, b'\x00')
    frame.extend(sender)
    if has_recipient:
        recipient = packet.recipient_id[:RECIPIENT_ID_SIZE].ljust(RECIPIENT_ID_SIZE, b'\x00')
        frame.extend(recipient)
    frame.extend(payload)
    if has_signature:
        frame.extend(packet.signature[:SIGNATURE_SIZE].ljust(SIGNATURE_SIZE, b'\x00'))

    raw = bytes(frame)
    if not apply_padding:
        return raw
    return pkcs7_pad(raw, optimal_block_size(len(raw)))

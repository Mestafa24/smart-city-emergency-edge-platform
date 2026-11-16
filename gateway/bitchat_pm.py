import asyncio
import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from bitchat_protocol import (
    BitchatPacket,
    MESSAGE_TYPE_ANNOUNCE,
    MESSAGE_TYPE_NOISE_ENCRYPTED,
    MESSAGE_TYPE_NOISE_HANDSHAKE,
    encode_packet,
    hex_peer_id_to_bytes,
)

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
HASH_LEN = 32
NOISE_NONCE_PREFIX = b"\x00\x00\x00\x00"

NOISE_PAYLOAD_PRIVATE_MESSAGE = 0x01
NOISE_PAYLOAD_READ_RECEIPT = 0x02
NOISE_PAYLOAD_DELIVERED = 0x03
NOISE_PAYLOAD_FILE_TRANSFER = 0x20

BROADCAST_RECIPIENT = b"\xff" * 8


class CipherState:
    def __init__(self, key: Optional[bytes] = None):
        self.key = key
        self.nonce = 0

    def has_key(self) -> bool:
        return self.key is not None

    def _build_nonce(self, nonce: int) -> bytes:
        # Southernstorm Noise ChaChaPoly uses a 32-bit zero prefix + 64-bit little-endian nonce.
        return NOISE_NONCE_PREFIX + int(nonce).to_bytes(8, "little")

    def encrypt_with_ad(self, ad: Optional[bytes], plaintext: bytes) -> bytes:
        if not self.has_key():
            return plaintext
        cipher = ChaCha20Poly1305(self.key)
        out = cipher.encrypt(self._build_nonce(self.nonce), plaintext, ad)
        self.nonce += 1
        return out

    def decrypt_with_ad(self, ad: Optional[bytes], ciphertext: bytes) -> bytes:
        if not self.has_key():
            return ciphertext
        cipher = ChaCha20Poly1305(self.key)
        out = cipher.decrypt(self._build_nonce(self.nonce), ciphertext, ad)
        self.nonce += 1
        return out
        
        
class NoiseXXBaseSession:
    def __init__(self, local_static_private_key: bytes, role: str):
        self.role = role
        self.local_static_private_key = x25519.X25519PrivateKey.from_private_bytes(local_static_private_key)
        self.local_static_public_key = self.local_static_private_key.public_key()

        self.e_priv: Optional[x25519.X25519PrivateKey] = None
        self.re_pub: Optional[x25519.X25519PublicKey] = None
        self.rs_pub: Optional[x25519.X25519PublicKey] = None

        self.ck, self.h = self._initialize_symmetric(PROTOCOL_NAME)

        # Android/southernstorm HandshakeState.start() mixes the prologue.
        # With no prologue this is still mixHash(empty).
        self._mix_hash(b"")

        self.handshake_cipher = CipherState()
        self.send_cipher: Optional[CipherState] = None
        self.recv_cipher: Optional[CipherState] = None
        self.established = False

    @staticmethod
    def _sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @classmethod
    def _initialize_symmetric(cls, protocol_name: bytes) -> tuple[bytes, bytes]:
        if len(protocol_name) <= HASH_LEN:
            h = protocol_name + (b"\x00" * (HASH_LEN - len(protocol_name)))
        else:
            h = cls._sha256(protocol_name)
        ck = h
        return ck, h

    @staticmethod
    def _hkdf2(chaining_key: bytes, input_key_material: bytes) -> tuple[bytes, bytes]:
        temp_key = hmac.new(chaining_key, input_key_material, hashlib.sha256).digest()
        out1 = hmac.new(temp_key, b"\x01", hashlib.sha256).digest()
        out2 = hmac.new(temp_key, out1 + b"\x02", hashlib.sha256).digest()
        return out1, out2

    def _mix_hash(self, data: bytes) -> None:
        self.h = self._sha256(self.h + data)

    def _mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = self._hkdf2(self.ck, input_key_material)
        self.handshake_cipher = CipherState(temp_k)

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.handshake_cipher.encrypt_with_ad(self.h, plaintext)
        self._mix_hash(ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.handshake_cipher.decrypt_with_ad(self.h, ciphertext)
        self._mix_hash(ciphertext)
        return plaintext

    @staticmethod
    def _pub_bytes(pubkey: x25519.X25519PublicKey) -> bytes:
        return pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _split_initiator(self) -> None:
        k1, k2 = self._hkdf2(self.ck, b"")
        self.send_cipher = CipherState(k1)
        self.recv_cipher = CipherState(k2)
        self.established = True

    def _split_responder(self) -> None:
        k1, k2 = self._hkdf2(self.ck, b"")
        self.recv_cipher = CipherState(k1)
        self.send_cipher = CipherState(k2)
        self.established = True

    def encrypt_transport(self, plaintext: bytes) -> bytes:
        if not self.established or self.send_cipher is None:
            raise RuntimeError("Noise session not established")
        current_nonce = self.send_cipher.nonce
        ciphertext = self.send_cipher.encrypt_with_ad(None, plaintext)
        return int(current_nonce).to_bytes(4, "big") + ciphertext

    def decrypt_transport(self, combined_payload: bytes) -> bytes:
        if not self.established or self.recv_cipher is None:
            raise RuntimeError("Noise session not established")
        if len(combined_payload) < 4:
            raise ValueError("Noise transport payload too short")
        nonce = int.from_bytes(combined_payload[:4], "big")
        ciphertext = combined_payload[4:]
        self.recv_cipher.nonce = nonce
        return self.recv_cipher.decrypt_with_ad(None, ciphertext)
        
        
class NoiseXXInitiatorSession(NoiseXXBaseSession):
    def __init__(self, local_static_private_key: bytes):
        super().__init__(local_static_private_key, role="initiator")

    def build_message_1(self) -> bytes:
        self.e_priv = x25519.X25519PrivateKey.generate()
        e_pub = self._pub_bytes(self.e_priv.public_key())
        self._mix_hash(e_pub)

        # Crucial Android/southernstorm compatibility step:
        # writeMessage(..., null, 0, 0) still calls encryptAndHash(empty payload).
        # With no key this emits zero bytes, but it still mixes the empty payload into h.
        self._encrypt_and_hash(b"")
        return e_pub

    def process_message_2(self, message_2: bytes) -> None:
        if self.e_priv is None:
            raise RuntimeError("Noise XX initiator state missing ephemeral key")
        if len(message_2) < 96:
            raise ValueError(f"Noise XX message 2 too short: {len(message_2)} bytes")

        re_bytes = message_2[:32]
        enc_static = message_2[32:80]
        enc_payload = message_2[80:]

        self.re_pub = x25519.X25519PublicKey.from_public_bytes(re_bytes)
        self._mix_hash(re_bytes)

        # ee
        self._mix_key(self.e_priv.exchange(self.re_pub))

        # s
        remote_static = self._decrypt_and_hash(enc_static)
        if len(remote_static) != 32:
            raise ValueError(f"Responder static key has invalid size: {len(remote_static)}")
        self.rs_pub = x25519.X25519PublicKey.from_public_bytes(remote_static)

        # es
        self._mix_key(self.e_priv.exchange(self.rs_pub))

        # encrypted empty handshake payload tag
        payload = self._decrypt_and_hash(enc_payload)
        if payload != b"":
            print(f"[PM] warning: Noise msg2 carried non-empty payload ({len(payload)} bytes)")

    def build_message_3(self) -> bytes:
        if self.re_pub is None:
            raise RuntimeError("Cannot build Noise XX message 3 before message 2")

        # s
        enc_static = self._encrypt_and_hash(self._pub_bytes(self.local_static_public_key))

        # se
        self._mix_key(self.local_static_private_key.exchange(self.re_pub))

        # empty encrypted handshake payload tag
        enc_payload = self._encrypt_and_hash(b"")

        self._split_initiator()
        return enc_static + enc_payload


class NoiseXXResponderSession(NoiseXXBaseSession):
    def __init__(self, local_static_private_key: bytes):
        super().__init__(local_static_private_key, role="responder")

    def process_message_1_and_build_message_2(self, message_1: bytes) -> bytes:
        if len(message_1) != 32:
            raise ValueError(f"Noise XX message 1 must be exactly 32 bytes, got {len(message_1)}")

        # Read initiator ephemeral e.
        self.re_pub = x25519.X25519PublicKey.from_public_bytes(message_1)
        self._mix_hash(message_1)

        # Read empty message-1 payload. No key yet: emits/consumes zero bytes, but hashes empty.
        self._decrypt_and_hash(b"")

        # Write responder message 2: e, ee, s, es, empty payload.
        self.e_priv = x25519.X25519PrivateKey.generate()
        e_pub = self._pub_bytes(self.e_priv.public_key())
        self._mix_hash(e_pub)

        # ee
        self._mix_key(self.e_priv.exchange(self.re_pub))

        # s
        enc_static = self._encrypt_and_hash(self._pub_bytes(self.local_static_public_key))

        # es: responder static with initiator ephemeral.
        self._mix_key(self.local_static_private_key.exchange(self.re_pub))

        # encrypted empty handshake payload tag
        enc_payload = self._encrypt_and_hash(b"")
        return e_pub + enc_static + enc_payload

    def process_message_3(self, message_3: bytes) -> None:
        if self.e_priv is None:
            raise RuntimeError("Noise XX responder state missing ephemeral key")
        if len(message_3) not in (48, 64):
            raise ValueError(f"Unexpected Noise XX message 3 size: {len(message_3)} bytes")

        enc_static = message_3[:48]
        enc_payload = message_3[48:]

        # s
        remote_static = self._decrypt_and_hash(enc_static)
        if len(remote_static) != 32:
            raise ValueError(f"Initiator static key has invalid size: {len(remote_static)}")
        self.rs_pub = x25519.X25519PublicKey.from_public_bytes(remote_static)

        # se: responder ephemeral with initiator static.
        self._mix_key(self.e_priv.exchange(self.rs_pub))

        # Android normally sends a 16-byte encrypted empty-payload tag here.
        # Accept 48-byte msg3 too because some comments/constants in the Android code say 48.
        if enc_payload:
            payload = self._decrypt_and_hash(enc_payload)
            if payload != b"":
                print(f"[PM] warning: Noise msg3 carried non-empty payload ({len(payload)} bytes)")
        else:
            # If no encrypted payload tag exists, still match no-key behavior only impossible here.
            # We do not hash anything extra.
            pass

        self._split_responder()


NoiseSessionT = Union[NoiseXXInitiatorSession, NoiseXXResponderSession]


@dataclass
class GatewayIdentity:
    static_private_key: bytes
    static_public_key: bytes
    signing_private_key: bytes
    signing_public_key: bytes
    peer_id_hex: str

    @classmethod
    def load_or_create(cls, base_path: str | os.PathLike = ".gateway_identity") -> "GatewayIdentity":
        base = Path(base_path)
        base.mkdir(parents=True, exist_ok=True)

        noise_priv_path = base / "noise_static_private.bin"
        noise_pub_path = base / "noise_static_public.bin"
        sign_priv_path = base / "ed25519_signing_private.bin"
        sign_pub_path = base / "ed25519_signing_public.bin"

        if noise_priv_path.exists() and noise_pub_path.exists():
            static_private = noise_priv_path.read_bytes()
            static_public = noise_pub_path.read_bytes()
        else:
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            static_private = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            static_public = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            noise_priv_path.write_bytes(static_private)
            noise_pub_path.write_bytes(static_public)

        if sign_priv_path.exists() and sign_pub_path.exists():
            signing_private = sign_priv_path.read_bytes()
            signing_public = sign_pub_path.read_bytes()
        else:
            sign_priv = ed25519.Ed25519PrivateKey.generate()
            sign_pub = sign_priv.public_key()
            signing_private = sign_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            signing_public = sign_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            sign_priv_path.write_bytes(signing_private)
            sign_pub_path.write_bytes(signing_public)

        peer_id_hex = hashlib.sha256(static_public).hexdigest()[:16]
        return cls(static_private, static_public, signing_private, signing_public, peer_id_hex)

    def sign(self, data: bytes) -> bytes:
        private = ed25519.Ed25519PrivateKey.from_private_bytes(self.signing_private_key)
        return private.sign(data)


def encode_tlv_private_message(message_id: str, content: str) -> bytes:
    msg_id_bytes = message_id.encode("utf-8")
    content_bytes = content.encode("utf-8")
    if len(msg_id_bytes) > 255 or len(content_bytes) > 255:
        raise ValueError("BitChat TLV private message fields must each be <= 255 bytes")

    out = bytearray()
    out.append(0x00)
    out.append(len(msg_id_bytes))
    out.extend(msg_id_bytes)
    out.append(0x01)
    out.append(len(content_bytes))
    out.extend(content_bytes)
    return bytes(out)
    
    
def wrap_noise_payload_private_message(tlv_payload: bytes) -> bytes:
    return bytes([NOISE_PAYLOAD_PRIVATE_MESSAGE]) + tlv_payload


def wrap_noise_payload_delivered(message_id: str) -> bytes:
    return bytes([NOISE_PAYLOAD_DELIVERED]) + message_id.encode("utf-8")


def wrap_noise_payload_read_receipt(message_id: str) -> bytes:
    return bytes([NOISE_PAYLOAD_READ_RECEIPT]) + message_id.encode("utf-8")


def encode_identity_announcement(nickname: str, noise_public_key: bytes, signing_public_key: bytes) -> bytes:
    nick = nickname.encode("utf-8")
    if len(nick) > 255 or len(noise_public_key) > 255 or len(signing_public_key) > 255:
        raise ValueError("IdentityAnnouncement TLV values must each be <= 255 bytes")
    out = bytearray()
    out.extend([0x01, len(nick)])
    out.extend(nick)
    out.extend([0x02, len(noise_public_key)])
    out.extend(noise_public_key)
    out.extend([0x03, len(signing_public_key)])
    out.extend(signing_public_key)
    return bytes(out)
    
    
class BitChatPrivateMessenger:
    """
    Pi-side BitChat private-message transport for the Safety Copilot.

    Supports:
      - Pi-initiated Noise XX handshakes.
      - Android-initiated Noise XX handshakes.
      - Private-message payloads.
      - Delivered/read ACK payloads.
      - Signed identity announces so Android can show a name instead of <@unknown>.
    """

    def __init__(self, char_uuid: str, identity_dir: str = ".gateway_identity"):
        self.char_uuid = char_uuid
        self.identity = GatewayIdentity.load_or_create(identity_dir)
        self._sessions: Dict[str, NoiseSessionT] = {}
        self._locks: Dict[str, asyncio.Lock] = {}

    def my_peer_id(self) -> str:
        return self.identity.peer_id_hex

    def _session_for(self, recipient_peer_id: str) -> NoiseSessionT:
        sess = self._sessions.get(recipient_peer_id)
        if sess is None:
            sess = NoiseXXInitiatorSession(self.identity.static_private_key)
            self._sessions[recipient_peer_id] = sess
        return sess

    def _new_initiator_session(self, peer_id: str) -> NoiseXXInitiatorSession:
        sess = NoiseXXInitiatorSession(self.identity.static_private_key)
        self._sessions[peer_id] = sess
        return sess

    def _new_responder_session(self, peer_id: str) -> NoiseXXResponderSession:
        sess = NoiseXXResponderSession(self.identity.static_private_key)
        self._sessions[peer_id] = sess
        return sess

    def _lock_for(self, recipient_peer_id: str) -> asyncio.Lock:
        lock = self._locks.get(recipient_peer_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[recipient_peer_id] = lock
        return lock

    def _frame_for_packet(self, packet: BitchatPacket, sign: bool = False) -> bytes:
        if sign:
            # Android signs/verifies the packet encoded with ttl forced to SYNC_TTL_HOPS=0
            # and without the signature field.
            signing_packet = BitchatPacket(
                version=packet.version,
                type=packet.type,
                ttl=0,
                timestamp=packet.timestamp,
                sender_id=packet.sender_id,
                recipient_id=packet.recipient_id,
                payload=packet.payload,
                signature=None,
            )
            data_for_signing = encode_packet(signing_packet, apply_padding=False)
            packet.signature = self.identity.sign(data_for_signing)
        return encode_packet(packet, apply_padding=False)

    async def _write_packet(
        self,
        client,
        recipient_peer_id: Optional[str],
        packet_type: int,
        payload: bytes,
        ttl: int = 7,
        sign: bool = False,
    ) -> None:
        recipient = hex_peer_id_to_bytes(recipient_peer_id) if recipient_peer_id else None
        packet = BitchatPacket(
            version=1,
            type=packet_type,
            ttl=ttl,
            timestamp=int(time.time() * 1000),
            sender_id=hex_peer_id_to_bytes(self.identity.peer_id_hex),
            recipient_id=recipient,
            payload=payload,
            signature=None,
        )
        frame = self._frame_for_packet(packet, sign=sign)
        await client.write_gatt_char(self.char_uuid, frame, response=False)

    async def send_announce(self, client, nickname: str = "Safety Copilot Gateway") -> None:
        payload = encode_identity_announcement(
            nickname=nickname,
            noise_public_key=self.identity.static_public_key,
            signing_public_key=self.identity.signing_public_key,
        )
        await self._write_packet(
            client,
            recipient_peer_id=None,
            packet_type=MESSAGE_TYPE_ANNOUNCE,
            payload=payload,
            ttl=7,
            sign=True,
        )
        print(f"[PM] sent signed gateway announce as @{nickname} peer={self.identity.peer_id_hex}")
        
    async def ensure_noise_session(self, client, recipient_peer_id: str) -> None:
        lock = self._lock_for(recipient_peer_id)
        async with lock:
            session = self._session_for(recipient_peer_id)
            if session.established:
                return

            if not isinstance(session, NoiseXXInitiatorSession) or session.e_priv is not None:
                session = self._new_initiator_session(recipient_peer_id)

            msg1 = session.build_message_1()
            await self._write_packet(client, recipient_peer_id, MESSAGE_TYPE_NOISE_HANDSHAKE, msg1)
            print(f"[PM] sent Noise XX msg1 to {recipient_peer_id}")

    async def process_handshake_packet(self, client, sender_peer_id: str, packet_payload: bytes) -> bool:
        """
        Returns True when a session is established after processing this packet.
        Handles both:
          - Android's reply to our msg1 (msg2, 96 bytes)
          - Android initiating a new handshake (msg1, 32 bytes)
          - Android's final msg3 after we responded as responder (48/64 bytes)
        """
        lock = self._lock_for(sender_peer_id)
        async with lock:
            # Android initiated handshake: msg1 is exactly 32 bytes.
            # Even if we already had a session, accept the rekey/restart and become responder.
            if len(packet_payload) == 32:
                session = self._new_responder_session(sender_peer_id)
                msg2 = session.process_message_1_and_build_message_2(packet_payload)
                await self._write_packet(client, sender_peer_id, MESSAGE_TYPE_NOISE_HANDSHAKE, msg2)
                print(f"[PM] processed Android Noise msg1 from {sender_peer_id}; sent msg2")
                return False

            session = self._sessions.get(sender_peer_id)
            if session is None:
                print(f"[PM] got Noise handshake from {sender_peer_id}, but no local session exists")
                return False

            if isinstance(session, NoiseXXInitiatorSession):
                if session.established:
                    print(f"[PM] ignoring extra handshake from {sender_peer_id}; initiator session already established")
                    return True
                if session.e_priv is None:
                    print(f"[PM] got msg2 from {sender_peer_id}, but initiator msg1 was never sent")
                    return False
                session.process_message_2(packet_payload)
                msg3 = session.build_message_3()
                await self._write_packet(client, sender_peer_id, MESSAGE_TYPE_NOISE_HANDSHAKE, msg3)
                print(f"[PM] completed Noise XX with {sender_peer_id}; sent msg3")
                return True

            if isinstance(session, NoiseXXResponderSession):
                if session.established:
                    print(f"[PM] ignoring extra handshake from {sender_peer_id}; responder session already established")
                    return True
                session.process_message_3(packet_payload)
                print(f"[PM] completed Android-initiated Noise XX with {sender_peer_id}")
                return True

            return False
            
    async def send_private_message(self, client, recipient_peer_id: str, content: str, ttl: int = 7, message_id: Optional[str] = None) -> str:
        lock = self._lock_for(recipient_peer_id)
        async with lock:
            session = self._session_for(recipient_peer_id)
            if not session.established:
                raise RuntimeError(f"Noise session with {recipient_peer_id} is not established yet")

            final_message_id = message_id or str(uuid.uuid4())
            tlv = encode_tlv_private_message(final_message_id, content)
            noise_payload = wrap_noise_payload_private_message(tlv)
            encrypted_transport = session.encrypt_transport(noise_payload)
            await self._write_packet(client, recipient_peer_id, MESSAGE_TYPE_NOISE_ENCRYPTED, encrypted_transport, ttl=ttl)
            print(f"[PM] sent private message to {recipient_peer_id} msg_id={final_message_id[:8]}...")
            return final_message_id

    async def send_delivery_ack(self, client, recipient_peer_id: str, message_id: str, ttl: int = 7) -> None:
        lock = self._lock_for(recipient_peer_id)
        async with lock:
            session = self._session_for(recipient_peer_id)
            if not session.established:
                raise RuntimeError(f"Noise session with {recipient_peer_id} is not established yet")
            encrypted_transport = session.encrypt_transport(wrap_noise_payload_delivered(message_id))
            await self._write_packet(client, recipient_peer_id, MESSAGE_TYPE_NOISE_ENCRYPTED, encrypted_transport, ttl=ttl)
            print(f"[PM] sent delivery ACK to {recipient_peer_id} for msg_id={message_id[:8]}...")

    async def send_read_receipt(self, client, recipient_peer_id: str, message_id: str, ttl: int = 7) -> None:
        lock = self._lock_for(recipient_peer_id)
        async with lock:
            session = self._session_for(recipient_peer_id)
            if not session.established:
                raise RuntimeError(f"Noise session with {recipient_peer_id} is not established yet")
            encrypted_transport = session.encrypt_transport(wrap_noise_payload_read_receipt(message_id))
            await self._write_packet(client, recipient_peer_id, MESSAGE_TYPE_NOISE_ENCRYPTED, encrypted_transport, ttl=ttl)
            print(f"[PM] sent read receipt to {recipient_peer_id} for msg_id={message_id[:8]}...")

    def decrypt_private_message(self, sender_peer_id: str, encrypted_transport_payload: bytes) -> dict:
        session = self._session_for(sender_peer_id)
        if not session.established:
            raise RuntimeError(f"Noise session with {sender_peer_id} is not established yet")
        plaintext = session.decrypt_transport(encrypted_transport_payload)
        return decode_noise_payload(plaintext)
        
        
def decode_tlv_private_message(tlv_payload: bytes) -> dict:
    offset = 0
    message_id = None
    content = None
    while offset + 2 <= len(tlv_payload):
        tlv_type = tlv_payload[offset]
        tlv_len = tlv_payload[offset + 1]
        offset += 2
        if offset + tlv_len > len(tlv_payload):
            raise ValueError("Truncated BitChat TLV private message")
        value = tlv_payload[offset:offset + tlv_len]
        offset += tlv_len
        if tlv_type == 0x00:
            message_id = value.decode("utf-8")
        elif tlv_type == 0x01:
            content = value.decode("utf-8")
    if message_id is None or content is None:
        raise ValueError("Missing TLV message_id or content")
    return {"type": "private_message", "message_id": message_id, "content": content}


def decode_noise_payload(noise_payload: bytes) -> dict:
    if not noise_payload:
        raise ValueError("Empty Noise payload")

    payload_type = noise_payload[0]
    data = noise_payload[1:]

    if payload_type == NOISE_PAYLOAD_PRIVATE_MESSAGE:
        return decode_tlv_private_message(data)

    if payload_type == NOISE_PAYLOAD_DELIVERED:
        return {
            "type": "delivered",
            "message_id": data.decode("utf-8", errors="replace"),
        }

    if payload_type == NOISE_PAYLOAD_READ_RECEIPT:
        return {
            "type": "read_receipt",
            "message_id": data.decode("utf-8", errors="replace"),
        }

    if payload_type == NOISE_PAYLOAD_FILE_TRANSFER:
        return {
            "type": "file_transfer",
            "raw_len": len(data),
        }

    return {
        "type": f"unknown_0x{payload_type:02x}",
        "raw_len": len(data),
    }


# Backwards-compatible name used by earlier code/comments.
def decode_noise_payload_private_message(noise_payload: bytes) -> dict:
    decoded = decode_noise_payload(noise_payload)
    if decoded.get("type") != "private_message":
        raise ValueError(f"Unsupported Noise payload type for private message decoder: {decoded.get('type')}")
    return decoded

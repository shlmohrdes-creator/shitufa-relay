"""
relay_server.py — Shitufa (שיתופא) relay server.

Run this manually on any machine reachable from the internet (a VPS, a home
server with a forwarded port, etc.) when you want peers that AREN'T on the
same local network to still be able to sync. Stop it whenever you don't
want that fallback active — devices simply keep working over LAN discovery
as before; the relay is 100% optional and stateless across restarts.

The relay is a BLIND multiplexing switch: it authenticates each device (by
proving they hold the private key matching the public key they present —
same RSA-4096 challenge/response scheme the app already uses between
peers) and then only ever forwards opaque, already-authenticated
application bytes between two devices' tunnels. It never decrypts,
inspects, or stores any file/chat/group content — see the module docstring
in relay_protocol.py for the exact framing.

Usage:
    python relay_server.py --port 57630
    python relay_server.py --port 57630 --host 0.0.0.0

Requires only the `cryptography` package (already a dependency of the app).
"""

import argparse
import asyncio
import base64
import datetime
import logging
import ssl
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

import relay_protocol as proto

logger = logging.getLogger("relay_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CERT_DIR = Path("relay_certs")
CERT_PATH = CERT_DIR / "relay_cert.pem"
KEY_PATH = CERT_DIR / "relay_key.pem"


def _ensure_relay_cert():
    """Generate a self-signed cert for the relay's own TLS listener, once.
    Clients don't verify this cert against a CA (same trust model the app
    already uses peer-to-peer) — it only protects the link from casual
    network eavesdropping; real identity is proven via the RSA challenge."""
    if CERT_PATH.exists() and KEY_PATH.exists():
        return
    from cryptography.hazmat.primitives.asymmetric import rsa

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shitufa-relay")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256(), default_backend())
    )
    KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    logger.info(f"Generated relay TLS cert at {CERT_DIR}/")


def _verify_signature(public_pem: bytes, challenge: bytes, signature: bytes) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_pem, backend=default_backend())
        pub.verify(
            signature,
            challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


class Tunnel:
    __slots__ = ("tunnel_id", "device_a", "device_b", "logical_port")

    def __init__(self, tunnel_id: bytes, device_a: str, device_b: str, logical_port: int):
        self.tunnel_id = tunnel_id
        self.device_a = device_a
        self.device_b = device_b
        self.logical_port = logical_port

    def other(self, device_id: str) -> str:
        return self.device_b if device_id == self.device_a else self.device_a


class RelayServer:
    def __init__(self):
        self.clients: dict[str, asyncio.StreamWriter] = {}       # device_id -> control writer
        self.write_locks: dict[str, asyncio.Lock] = {}            # one writer per socket -> needs a lock
        self.tunnels: dict[bytes, Tunnel] = {}                    # tunnel_id -> Tunnel

    async def _send(self, device_id: str, frame_type: int, body: bytes):
        writer = self.clients.get(device_id)
        if not writer:
            return False
        lock = self.write_locks.setdefault(device_id, asyncio.Lock())
        try:
            async with lock:
                await proto.write_frame(writer, frame_type, body)
            return True
        except Exception:
            return False

    async def _send_json(self, device_id: str, frame_type: int, obj: dict):
        return await self._send(device_id, frame_type, __import__("json").dumps(obj).encode())

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        device_id = None
        try:
            frame_type, body = await proto.read_frame(reader)
            if frame_type != proto.REGISTER:
                writer.close()
                return
            msg = proto.read_json_body(body)
            public_pem = base64.b64decode(msg["public_key"])

            import hashlib
            device_id = hashlib.sha256(public_pem).hexdigest()[:16]

            nonce = uuid.uuid4().bytes + uuid.uuid4().bytes  # 32 random bytes
            await proto.write_json_frame(writer, proto.CHALLENGE, {"nonce": base64.b64encode(nonce).decode()})

            frame_type, body = await proto.read_frame(reader)
            if frame_type != proto.CHALLENGE_RESPONSE:
                writer.close()
                return
            resp = proto.read_json_body(body)
            signature = base64.b64decode(resp["signature"])

            if not _verify_signature(public_pem, nonce, signature):
                await proto.write_json_frame(writer, proto.REGISTER_FAIL, {"reason": "bad_signature"})
                writer.close()
                return

            # Kick any stale connection for the same device_id (reconnect case)
            old = self.clients.get(device_id)
            if old and old is not writer:
                try:
                    old.close()
                except Exception:
                    pass

            self.clients[device_id] = writer
            await proto.write_json_frame(writer, proto.REGISTER_OK, {"device_id": device_id})
            logger.info(f"[Relay] Device {device_id[:8]} registered ({peer})")

            await self._client_loop(device_id, reader, writer)

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            logger.debug(f"[Relay] Connection error ({peer}): {e}")
        finally:
            if device_id and self.clients.get(device_id) is writer:
                del self.clients[device_id]
                logger.info(f"[Relay] Device {device_id[:8]} disconnected")
                # Tear down any tunnels this device was party to
                dead = [tid for tid, t in self.tunnels.items() if device_id in (t.device_a, t.device_b)]
                for tid in dead:
                    t = self.tunnels.pop(tid, None)
                    if t:
                        other = t.other(device_id)
                        await self._send(other, proto.CLOSE, tid)
            try:
                writer.close()
            except Exception:
                pass

    async def _client_loop(self, device_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        while True:
            frame_type, body = await proto.read_frame(reader)

            if frame_type == proto.PING:
                await proto.write_frame(writer, proto.PONG, b"")

            elif frame_type == proto.OPEN:
                msg = proto.read_json_body(body)
                tunnel_id = bytes.fromhex(msg["tunnel_id"])
                target = msg["target_device_id"]
                logical_port = int(msg["logical_port"])

                if target not in self.clients:
                    await self._send_json(device_id, proto.OPEN_RESULT,
                                           {"tunnel_id": tunnel_id.hex(), "status": "offline"})
                    continue

                self.tunnels[tunnel_id] = Tunnel(tunnel_id, device_id, target, logical_port)
                ok = await self._send_json(target, proto.OPEN_NOTIFY, {
                    "tunnel_id": tunnel_id.hex(),
                    "from_device_id": device_id,
                    "logical_port": logical_port,
                })
                if not ok:
                    self.tunnels.pop(tunnel_id, None)
                    await self._send_json(device_id, proto.OPEN_RESULT,
                                           {"tunnel_id": tunnel_id.hex(), "status": "offline"})

            elif frame_type == proto.OPEN_ACK:
                msg = proto.read_json_body(body)
                tunnel_id = bytes.fromhex(msg["tunnel_id"])
                t = self.tunnels.get(tunnel_id)
                if t:
                    initiator = t.other(device_id)  # the one who is NOT the target replying
                    await self._send_json(initiator, proto.OPEN_RESULT,
                                           {"tunnel_id": tunnel_id.hex(), "status": msg.get("status", "error")})
                    if msg.get("status") != "ok":
                        self.tunnels.pop(tunnel_id, None)

            elif frame_type in (proto.DATA, proto.CLOSE):
                tunnel_id = body[:16]
                t = self.tunnels.get(tunnel_id)
                if not t:
                    continue
                other = t.other(device_id)
                await self._send(other, frame_type, body)
                if frame_type == proto.CLOSE:
                    self.tunnels.pop(tunnel_id, None)

            else:
                logger.debug(f"[Relay] Unknown frame type {frame_type} from {device_id[:8]}")


async def main():
    parser = argparse.ArgumentParser(description="Shitufa relay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=57630)
    args = parser.parse_args()

    _ensure_relay_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    server_state = RelayServer()
    server = await asyncio.start_server(server_state.handle_client, args.host, args.port, ssl=ctx)
    logger.info(f"[Relay] Listening on {args.host}:{args.port} (TLS)")
    logger.info("[Relay] Stop with Ctrl+C whenever you don't want internet fallback active.")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[Relay] Shutting down.")

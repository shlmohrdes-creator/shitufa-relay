"""
relay_server.py — Shitufa (שיתופא) relay server (WebSocket transport).

Run this on any machine reachable from the internet — including a platform
like Render that only exposes HTTP(S)/WebSocket externally (not arbitrary
raw TCP ports). Peers who aren't reachable on the same local network can
still be synced with over the internet through this relay. Stop it whenever
you don't want that fallback active — devices simply keep working over LAN
discovery as before; the relay is 100% optional and stateless across
restarts.

The relay is a BLIND multiplexing switch: it authenticates each device (by
proving they hold the private key matching the public key they present —
same RSA-4096 challenge/response scheme the app already uses between
peers) and then only ever forwards opaque, already-authenticated
application bytes between two devices' tunnels. It never decrypts,
inspects, or stores any file/chat/group content — see the module docstring
in relay_protocol.py for the exact framing.

Transport note: this version speaks WebSocket instead of raw TCP+TLS. TLS
itself is handled by the hosting platform (Render terminates HTTPS/WSS at
its edge and forwards plain traffic to this process) — this script does
NOT do its own TLS termination. If you deploy this on a plain VPS instead
(with no TLS-terminating proxy in front of it), put it behind something
like Caddy/nginx for wss://, or accept that connections will be ws://
(unencrypted at the transport level — the RSA challenge/response still
proves identity, but traffic itself won't be encrypted at this layer).

Usage:
    python relay_server.py --port 57630
    (Render and similar platforms set the $PORT env var automatically —
    that takes priority over --port when present.)

Requires: websockets, cryptography
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import uuid

import websockets
from websockets.exceptions import ConnectionClosed

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import relay_protocol as proto

logger = logging.getLogger("relay_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16MB — plenty for chunked file data


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
        self.clients: dict[str, "websockets.asyncio.server.ServerConnection"] = {}  # device_id -> websocket
        self.write_locks: dict[str, asyncio.Lock] = {}   # one socket -> needs a lock for concurrent sends
        self.tunnels: dict[bytes, Tunnel] = {}           # tunnel_id -> Tunnel

    async def _send(self, device_id: str, frame_type: int, body: bytes) -> bool:
        ws = self.clients.get(device_id)
        if not ws:
            return False
        lock = self.write_locks.setdefault(device_id, asyncio.Lock())
        try:
            async with lock:
                await ws.send(proto.pack_ws_message(frame_type, body))
            return True
        except Exception:
            return False

    async def _send_json(self, device_id: str, frame_type: int, obj: dict) -> bool:
        return await self._send(device_id, frame_type, json.dumps(obj).encode())

    @staticmethod
    def _as_bytes(raw) -> bytes:
        return raw if isinstance(raw, bytes) else raw.encode("utf-8")

    async def handle_client(self, websocket):
        peer = websocket.remote_address
        device_id = None
        try:
            raw = await websocket.recv()
            frame_type, body = proto.unpack_ws_message(self._as_bytes(raw))
            if frame_type != proto.REGISTER:
                await websocket.close()
                return
            msg = proto.read_json_body(body)
            public_pem = base64.b64decode(msg["public_key"])
            device_id = hashlib.sha256(public_pem).hexdigest()[:16]

            nonce = uuid.uuid4().bytes + uuid.uuid4().bytes  # 32 random bytes
            await websocket.send(proto.pack_ws_message(
                proto.CHALLENGE, json.dumps({"nonce": base64.b64encode(nonce).decode()}).encode()
            ))

            raw = await websocket.recv()
            frame_type, body = proto.unpack_ws_message(self._as_bytes(raw))
            if frame_type != proto.CHALLENGE_RESPONSE:
                await websocket.close()
                return
            resp = proto.read_json_body(body)
            signature = base64.b64decode(resp["signature"])

            if not _verify_signature(public_pem, nonce, signature):
                await websocket.send(proto.pack_ws_message(
                    proto.REGISTER_FAIL, json.dumps({"reason": "bad_signature"}).encode()
                ))
                await websocket.close()
                return

            # Kick any stale connection for the same device_id (reconnect case)
            old = self.clients.get(device_id)
            if old and old is not websocket:
                try:
                    await old.close()
                except Exception:
                    pass

            self.clients[device_id] = websocket
            await websocket.send(proto.pack_ws_message(
                proto.REGISTER_OK, json.dumps({"device_id": device_id}).encode()
            ))
            logger.info(f"[Relay] Device {device_id[:8]} registered ({peer})")

            await self._client_loop(device_id, websocket)

        except ConnectionClosed:
            pass
        except Exception as e:
            # NOTE: temporarily raised from logger.debug to logger.info so this
            # actually shows up with the server's current logging.basicConfig
            # level=logging.INFO. logger.debug() here was being silently
            # swallowed, which is why repeated connect/close cycles produced
            # no visible error at all. Revert to logger.debug once the root
            # cause of the reconnect loop is found and fixed.
            logger.info(f"[Relay] Connection error ({peer}): {e!r}")
        finally:
            if device_id and self.clients.get(device_id) is websocket:
                del self.clients[device_id]
                logger.info(f"[Relay] Device {device_id[:8]} disconnected")
                dead = [tid for tid, t in self.tunnels.items() if device_id in (t.device_a, t.device_b)]
                for tid in dead:
                    t = self.tunnels.pop(tid, None)
                    if t:
                        other = t.other(device_id)
                        await self._send(other, proto.CLOSE, tid)

    async def _client_loop(self, device_id: str, websocket):
        async for raw in websocket:
            frame_type, body = proto.unpack_ws_message(self._as_bytes(raw))

            if frame_type == proto.PING:
                await websocket.send(proto.pack_ws_message(proto.PONG, b""))

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
                logger.info(f"[Relay] Unknown frame type {frame_type} from {device_id[:8]}")


async def main():
    parser = argparse.ArgumentParser(description="Shitufa relay server (WebSocket)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=57630)
    args = parser.parse_args()

    port = int(os.environ.get("PORT", args.port))

    server_state = RelayServer()
    async with websockets.serve(server_state.handle_client, args.host, port, max_size=MAX_MESSAGE_SIZE):
        logger.info(f"[Relay] Listening on {args.host}:{port} (WebSocket)")
        logger.info("[Relay] Stop whenever you don't want internet fallback active.")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[Relay] Shutting down.")

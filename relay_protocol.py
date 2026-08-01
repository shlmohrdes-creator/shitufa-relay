"""
relay_protocol.py — Shitufa (שיתופא) relay wire format.

Used by BOTH relay_server.py (runs on the machine you designate as the
relay) and relay_client.py (runs inside the app, on every device).

Frame format on the wire (single persistent TCP+TLS connection per device):

    [4 bytes big-endian frame length] [1 byte frame type] [body]

Control frames (REGISTER..OPEN_RESULT) carry a JSON body.
DATA/CLOSE frames carry a binary body: 16-byte tunnel_id + raw payload.

Design notes:
  - Each device keeps ONE persistent connection to the relay ("control
    connection"). All tunnels to/from that device are multiplexed over it —
    no extra listening ports, no per-tunnel connections. This is the same
    approach used by DERP/ngrok-style relays and keeps the relay trivial to
    operate (one port, one process).
  - The relay never terminates the *application* protocol (TLS handshake
    for file transfers, JSON for chat/invites/etc.) — it only forwards
    opaque DATA frames between the two devices' control connections. What
    those bytes mean is entirely up to the two endpoints.
"""

import asyncio
import json
import struct

MAX_FRAME_BODY = 8 * 1024 * 1024  # 8MB per frame — plenty for chunked file data

# Frame types
REGISTER            = 0x01  # client -> server: {"public_key": base64 pem}
CHALLENGE           = 0x02  # server -> client: {"nonce": base64}
CHALLENGE_RESPONSE  = 0x03  # client -> server: {"signature": base64}
REGISTER_OK         = 0x04  # server -> client: {"device_id": hex}
REGISTER_FAIL       = 0x05  # server -> client: {"reason": str}
OPEN                = 0x06  # client -> server: {"tunnel_id": hex, "target_device_id": hex, "logical_port": int}
OPEN_NOTIFY         = 0x07  # server -> target client: {"tunnel_id": hex, "from_device_id": hex, "logical_port": int}
OPEN_ACK            = 0x08  # target client -> server: {"tunnel_id": hex, "status": "ok"|"error"}
OPEN_RESULT         = 0x09  # server -> initiator client: {"tunnel_id": hex, "status": "ok"|"offline"|"error"}
DATA                = 0x0A  # either direction, binary: tunnel_id(16) + payload
CLOSE               = 0x0B  # either direction, binary: tunnel_id(16)
PING                = 0x0C  # keepalive, empty body
PONG                = 0x0D  # keepalive reply, empty body


class FrameError(Exception):
    pass


async def write_frame(writer: asyncio.StreamWriter, frame_type: int, body: bytes):
    if len(body) > MAX_FRAME_BODY:
        raise FrameError(f"frame body too large ({len(body)} bytes)")
    writer.write(struct.pack(">IB", len(body) + 1, frame_type) + body)
    await writer.drain()


async def write_json_frame(writer: asyncio.StreamWriter, frame_type: int, obj: dict):
    await write_frame(writer, frame_type, json.dumps(obj).encode("utf-8"))


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """Returns (frame_type, body). Raises asyncio.IncompleteReadError on EOF."""
    header = await reader.readexactly(5)
    total_len, frame_type = struct.unpack(">IB", header)
    body_len = total_len - 1
    body = await reader.readexactly(body_len) if body_len > 0 else b""
    return frame_type, body


def read_json_body(body: bytes) -> dict:
    return json.loads(body.decode("utf-8"))


def pack_data_frame(tunnel_id: bytes, payload: bytes) -> bytes:
    return tunnel_id + payload


def unpack_data_frame(body: bytes) -> tuple[bytes, bytes]:
    return body[:16], body[16:]


# ── WebSocket transport variant ──────────────────────────────────────────────
# Used when the relay runs behind a platform (Render, etc.) that only exposes
# HTTP(S)/WebSocket externally, rather than a raw TCP+TLS port. A WebSocket
# message already has well-defined boundaries, so we don't need the 4-byte
# length prefix used above for the raw-TCP framing — each frame is just its
# 1-byte type plus body, sent as a single binary WS message.

def pack_ws_message(frame_type: int, body: bytes) -> bytes:
    return struct.pack(">B", frame_type) + body


def unpack_ws_message(data: bytes) -> tuple[int, bytes]:
    return data[0], data[1:]

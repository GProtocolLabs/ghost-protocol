# Ghost Protocol Node Server
#
# MIT License
# Copyright (c) 2026 GProtocolLabs
#
# This software is provided "as is", without warranty of any kind.

import os
import sys
import json
import time
import uuid
import sqlite3
import asyncio
import argparse
import base64
import socket
from typing import Dict, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import websockets

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
parser.add_argument("--peers", type=str, default=os.environ.get("PEERS", ""))
parser.add_argument("--node-id", type=str, default=os.environ.get("NODE_ID", ""))
parser.add_argument("--db", type=str, default=os.environ.get("NODE_DB", ""))
parser.add_argument("--udp-port", type=int, default=int(os.environ.get("UDP_PORT", 9000)))
parser.add_argument("--udp-discover", type=str, default=os.environ.get("UDP_DISCOVER", "true"))
known_args, _ = parser.parse_known_args()

PORT = known_args.port
PEER_URLS = [p.strip() for p in known_args.peers.split(",") if p.strip()]
NODE_ID = known_args.node_id or f"node-{uuid.uuid4().hex[:8]}"
DB_PATH = known_args.db or os.path.join(BASE_DIR, f"node_{PORT}.db")
UDP_PORT = known_args.udp_port
UDP_DISCOVER = known_args.udp_discover.lower() in ("true", "1", "yes")

MAX_TTL = 6
SEEN_MSG_EXPIRY = 300
UDP_ANNOUNCE_INTERVAL = 30   # seconds between UDP hello broadcasts
UDP_PEER_TIMEOUT = 120       # seconds before considering a UDP-discovered peer gone

# --------------------------------------------------------------------------
# Banco de dados
# --------------------------------------------------------------------------

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db_connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS local_users (
            user_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            registered_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS offline_queue (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            envelope TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS seen_messages (
            id TEXT PRIMARY KEY,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_offline_user ON offline_queue(user_id);
    """)
    try:
        conn.execute("ALTER TABLE local_users ADD COLUMN display_name TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

def cleanup_seen_messages():
    conn = db_connect()
    conn.execute("DELETE FROM seen_messages WHERE created_at < ?", (time.time() - SEEN_MSG_EXPIRY,))
    conn.commit()
    conn.close()

# --------------------------------------------------------------------------
# Estado em memória
# --------------------------------------------------------------------------

local_clients: Dict[str, WebSocket] = {}
peer_connections: Dict[str, "PeerLink"] = {}
pending_friend_requests: Dict[str, dict] = {}
peer_users: Dict[str, list] = {}  # node_id -> [{user_id, display_name}]

class PeerLink:
    def __init__(self, node_id, send_fn):
        self.node_id = node_id
        self._send_fn = send_fn

    async def send(self, data: dict):
        await self._send_fn(json.dumps(data))

# --------------------------------------------------------------------------
# UDP Discovery (LAN auto-peering)
# --------------------------------------------------------------------------

# Track UDP-discovered peers: node_id -> {"ip", "port", "last_seen"}
udp_peers: Dict[str, dict] = {}
# Prevent duplicate outbound connections for the same URL
pending_urls: Set[str] = set()

def get_local_ip() -> str:
    """Best-effort local LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

async def udp_broadcast_loop():
    """Periodically send a UDP hello packet to the LAN broadcast address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    local_ip = get_local_ip()
    payload = json.dumps({
        "type": "hello",
        "node_id": NODE_ID,
        "ip": local_ip,
        "port": PORT,
    }).encode("utf-8")

    print(f"[udp] Broadcasting presence on UDP port {UDP_PORT} (LAN IP: {local_ip}, WS port: {PORT})")

    while True:
        try:
            sock.sendto(payload, ("<broadcast>", UDP_PORT))
        except Exception as e:
            print(f"[udp] Broadcast error: {e}")
        await asyncio.sleep(UDP_ANNOUNCE_INTERVAL)

class _UDPDiscoveryProtocol(asyncio.DatagramProtocol):
    """DatagramProtocol-based UDP listener.

    Necessário porque loop.sock_recvfrom() não existe no ProactorEventLoop
    (o event loop padrão do asyncio no Windows), só no SelectorEventLoop.
    create_datagram_endpoint funciona em ambos.
    """

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(_handle_udp_hello(data, addr))

    def error_received(self, exc):
        print(f"[udp] Listen error: {exc}")


async def _handle_udp_hello(data: bytes, addr):
    try:
        msg = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return

    if msg.get("type") != "hello":
        return

    remote_node_id = msg.get("node_id")
    remote_ip = msg.get("ip", addr[0])
    remote_port = msg.get("port")

    if not remote_node_id or not remote_port:
        return

    # Ignore our own broadcasts
    if remote_node_id == NODE_ID:
        return

    ws_url = f"ws://{remote_ip}:{remote_port}/ws/peer"

    # Already connected or already connecting?  Check both the real node_id
    # and the pending URL to avoid creating duplicate outbound tasks.
    already_connected = remote_node_id in peer_connections or ws_url in pending_urls
    if not already_connected:
        for key in peer_connections:
            if ws_url in key or remote_node_id in key:
                already_connected = True
                break
    if already_connected:
        udp_peers[remote_node_id] = {"ip": remote_ip, "port": remote_port, "last_seen": time.time()}
        return

    # Tie-breaking: only the node with the smaller node_id initiates.
    # This prevents duplicate connections when both nodes discover each other
    # at the same time via UDP.
    if NODE_ID >= remote_node_id:
        # We are not the smaller one — the other node will connect to us.
        # Still track it so we know it's out there.
        udp_peers[remote_node_id] = {"ip": remote_ip, "port": remote_port, "last_seen": time.time()}
        return

    # New node discovered — connect via WebSocket
    pending_urls.add(ws_url)
    print(f"[udp] Discovered new node: {remote_node_id} at {ws_url}")
    udp_peers[remote_node_id] = {"ip": remote_ip, "port": remote_port, "last_seen": time.time()}
    asyncio.create_task(connect_to_peer(ws_url))


async def udp_listen_loop():
    """Listen for UDP hello packets from other nodes on the LAN.

    Usa create_datagram_endpoint em vez de socket bruto + loop.sock_recvfrom
    porque este último não é suportado pelo ProactorEventLoop do Windows.
    """
    loop = asyncio.get_event_loop()

    reuse_kwargs = {}
    if sys.platform != "win32":
        # SO_REUSEPORT não existe no Windows; nesse caso deixamos o asyncio
        # usar apenas o comportamento padrão de bind.
        reuse_kwargs["reuse_port"] = True

    transport, _protocol = await loop.create_datagram_endpoint(
        _UDPDiscoveryProtocol,
        local_addr=("0.0.0.0", UDP_PORT),
        **reuse_kwargs,
    )

    print(f"[udp] Listening for peer discovery on UDP port {UDP_PORT}")

    try:
        # Mantém a task viva; o recebimento real acontece em datagram_received
        while True:
            await asyncio.sleep(3600)
    finally:
        transport.close()

async def udp_cleanup_loop():
    """Remove UDP-discovered peers that haven't announced in UDP_PEER_TIMEOUT seconds."""
    while True:
        await asyncio.sleep(30)
        now = time.time()
        stale = [
            nid for nid, info in udp_peers.items()
            if now - info.get("last_seen", 0) > UDP_PEER_TIMEOUT
        ]
        for nid in stale:
            if nid in peer_connections:
                print(f"[udp] Peer {nid} timed out (no UDP announcements), disconnecting")
                peer_connections.pop(nid, None)
                peer_users.pop(nid, None)
            udp_peers.pop(nid, None)
        if stale:
            print(f"[udp] Cleaned up {len(stale)} stale peer(s)")

# --------------------------------------------------------------------------
# Helpers: peer user sharing
# --------------------------------------------------------------------------

def get_local_user_list():
    conn = db_connect()
    rows = conn.execute("SELECT user_id, display_name FROM local_users").fetchall()
    conn.close()
    return [{"user_id": r["user_id"], "display_name": r["display_name"] or ""} for r in rows]

async def broadcast_peer_user_joined(user_id: str, display_name: str):
    for node_id, link in list(peer_connections.items()):
        if node_id.startswith("pending:"):
            continue
        try:
            await link.send({
                "type": "peer_user_joined",
                "user_id": user_id,
                "display_name": display_name,
            })
        except Exception:
            pass

async def broadcast_peer_user_left(user_id: str):
    for node_id, link in list(peer_connections.items()):
        if node_id.startswith("pending:"):
            continue
        try:
            await link.send({
                "type": "peer_user_left",
                "user_id": user_id,
            })
        except Exception:
            pass

async def send_peer_users(link: PeerLink):
    users = get_local_user_list()
    try:
        await link.send({"type": "peer_users", "users": users})
    except Exception:
        pass

async def relay_friend_request_to_peer(to_user: str, request_data: dict):
    for node_id, pu_list in peer_users.items():
        if any(u["user_id"] == to_user for u in pu_list):
            link = peer_connections.get(node_id)
            if link:
                try:
                    await link.send({
                        "type": "peer_friend_request",
                        **request_data,
                    })
                    return True
                except Exception:
                    pass
    return False

async def relay_friend_response_to_peer(target_user: str, resp_data: dict):
    for node_id, pu_list in peer_users.items():
        if any(u["user_id"] == target_user for u in pu_list):
            link = peer_connections.get(node_id)
            if link:
                try:
                    await link.send(resp_data)
                    return True
                except Exception:
                    pass
    return False

def is_peer_user(user_id: str) -> bool:
    for pu_list in peer_users.values():
        if any(u["user_id"] == user_id for u in pu_list):
            return True
    return False

async def relay_event_to_peer(to_user: str, event: str, data: dict):
    """Relay typing/receipt/reaction/etc events to the peer that hosts to_user."""
    for node_id, pu_list in peer_users.items():
        if any(u["user_id"] == to_user for u in pu_list):
            link = peer_connections.get(node_id)
            if link:
                try:
                    await link.send({"type": event, **data})
                    return True
                except Exception:
                    pass
    return False

# --------------------------------------------------------------------------
# App FastAPI
# --------------------------------------------------------------------------

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/api/status")
def status():
    conn = db_connect()
    n_users = conn.execute("SELECT COUNT(*) c FROM local_users").fetchone()["c"]
    conn.close()
    return JSONResponse({
        "node_id": NODE_ID, "port": PORT,
        "local_users": n_users,
        "peers_connected": list(peer_connections.keys()),
        "peers_configured": PEER_URLS,
    })

@app.get("/api/lookup/{user_id}")
def lookup_public_key(user_id: str):
    conn = db_connect()
    row = conn.execute("SELECT public_key FROM local_users WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return JSONResponse({"error": "nao encontrado neste no"}, status_code=404)
    return JSONResponse({"user_id": user_id, "public_key": json.loads(row["public_key"])})

@app.get("/api/network")
def network_view():
    """Visual network map: this node + peers + their users."""
    conn = db_connect()
    local_rows = conn.execute("SELECT user_id, display_name FROM local_users").fetchall()
    conn.close()
    local_users = [{"user_id": r["user_id"], "display_name": r["display_name"] or ""} for r in local_rows]

    nodes = [{
        "node_id": NODE_ID,
        "is_self": True,
        "connected": True,
        "users": local_users,
        "url": f"ws://{NODE_ID}:{PORT}/ws/peer",
    }]

    for peer_id, link in peer_connections.items():
        if peer_id.startswith("pending:"):
            continue
        peer_user_list = peer_users.get(peer_id, [])
        nodes.append({
            "node_id": peer_id,
            "is_self": False,
            "connected": True,
            "users": peer_user_list,
        })

    return JSONResponse({"nodes": nodes})


@app.post("/api/connect")
async def connect_to_peer_api(request: dict):
    """Connect to a peer on demand (POST JSON body: {"url": "ws://..."})."""
    peer_url = request.get("url", "")
    if not peer_url:
        return JSONResponse({"error": "missing url"}, status_code=400)
    # check if already connected
    for existing in peer_connections:
        if peer_url in existing:
            return JSONResponse({"status": "already_connected", "node_id": existing})
    asyncio.create_task(connect_to_peer(peer_url))
    return JSONResponse({"status": "connecting", "url": peer_url})


@app.get("/api/peers")
def peers_list():
    """Detailed peer list with user counts."""
    peers = []
    for peer_id in peer_connections:
        if peer_id.startswith("pending:"):
            continue
        peer_user_list = peer_users.get(peer_id, [])
        peers.append({
            "node_id": peer_id,
            "user_count": len(peer_user_list),
            "users": peer_user_list,
        })
    return JSONResponse({"peers": peers, "peers_configured": PEER_URLS})


@app.get("/api/local-users")
def local_users_list():
    users = get_local_user_list()
    seen = set(u["user_id"] for u in users)
    for pu_list in peer_users.values():
        for pu in pu_list:
            if pu["user_id"] not in seen:
                users.append(pu)
                seen.add(pu["user_id"])
    return JSONResponse({"users": users})

# --------------------------------------------------------------------------
# Roteamento de envelopes
# --------------------------------------------------------------------------

def mark_seen(msg_id: str) -> bool:
    conn = db_connect()
    try:
        conn.execute("INSERT INTO seen_messages (id, created_at) VALUES (?,?)", (msg_id, time.time()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def is_local_user(user_id: str) -> bool:
    conn = db_connect()
    row = conn.execute("SELECT 1 FROM local_users WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    return row is not None

def queue_offline(user_id: str, envelope: dict):
    conn = db_connect()
    conn.execute(
        "INSERT INTO offline_queue (id, user_id, envelope, created_at) VALUES (?,?,?,?)",
        (uuid.uuid4().hex, user_id, json.dumps(envelope), time.time()),
    )
    conn.commit()
    conn.close()

async def deliver_or_queue_locally(to_user: str, envelope: dict):
    ws = local_clients.get(to_user)
    if ws:
        try:
            await ws.send_text(json.dumps({"type": "message", "envelope": envelope}))
            return
        except Exception:
            pass
    queue_offline(to_user, envelope)

async def route_envelope(envelope: dict, msg_id: str, ttl: int, exclude_peer: str = None):
    to_user = envelope.get("to")
    if is_local_user(to_user):
        await deliver_or_queue_locally(to_user, envelope)
        return
    if ttl <= 0:
        return
    for node_id, link in list(peer_connections.items()):
        if node_id == exclude_peer:
            continue
        try:
            await link.send({
                "type": "relay", "msg_id": msg_id,
                "envelope": envelope, "ttl": ttl - 1,
            })
        except Exception:
            pass

# --------------------------------------------------------------------------
# WebSocket: clientes
# --------------------------------------------------------------------------

@app.websocket("/ws/client")
async def client_ws(ws: WebSocket):
    await ws.accept()
    my_user_id = None
    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            if msg_type == "register":
                user_id = data.get("user_id")
                public_key = data.get("public_key")
                display_name = data.get("display_name", "")
                if not user_id or not public_key:
                    continue
                conn = db_connect()
                conn.execute(
                    "INSERT INTO local_users (user_id, public_key, display_name, registered_at) VALUES (?,?,?,?) "
                    "ON CONFLICT(user_id) DO UPDATE SET public_key=excluded.public_key, display_name=excluded.display_name",
                    (user_id, json.dumps(public_key), display_name, time.time()),
                )
                conn.commit()
                conn.close()
                my_user_id = user_id
                local_clients[user_id] = ws
                await ws.send_text(json.dumps({"type": "registered", "node_id": NODE_ID}))

                # broadcast to peers
                await broadcast_peer_user_joined(user_id, display_name)

                # deliver offline messages
                conn = db_connect()
                rows = conn.execute(
                    "SELECT id, envelope FROM offline_queue WHERE user_id=? ORDER BY created_at",
                    (user_id,),
                ).fetchall()
                for row in rows:
                    await ws.send_text(json.dumps({"type": "message", "envelope": json.loads(row["envelope"])}))
                conn.execute("DELETE FROM offline_queue WHERE user_id=?", (user_id,))
                conn.commit()
                conn.close()

            elif msg_type == "send":
                envelope = data.get("envelope")
                if not envelope or not envelope.get("to") or not envelope.get("from"):
                    continue
                msg_id = uuid.uuid4().hex
                mark_seen(msg_id)
                await route_envelope(envelope, msg_id, ttl=MAX_TTL)

            elif msg_type == "friend_request":
                if not my_user_id:
                    await ws.send_text(json.dumps({"type": "error", "message": "Registre-se primeiro"}))
                    continue
                to_user = data.get("to")
                from_alias = data.get("from_alias", "")
                card = data.get("card")
                if not to_user or not card:
                    continue
                request_id = uuid.uuid4().hex

                # Try local delivery first
                recipient_ws = local_clients.get(to_user)
                if recipient_ws:
                    pending_friend_requests[request_id] = {
                        "from": my_user_id, "to": to_user,
                        "from_card": card, "from_alias": from_alias,
                    }
                    await recipient_ws.send_text(json.dumps({
                        "type": "friend_request", "request_id": request_id,
                        "from": my_user_id, "from_alias": from_alias, "card": card,
                    }))
                    await ws.send_text(json.dumps({"type": "friend_request_sent", "request_id": request_id}))
                else:
                    # Try relay to peer
                    req_data = {
                        "request_id": request_id,
                        "from": my_user_id, "to": to_user,
                        "from_alias": from_alias, "card": card,
                    }
                    relayed = await relay_friend_request_to_peer(to_user, req_data)
                    if relayed:
                        pending_friend_requests[request_id] = {
                            "from": my_user_id, "to": to_user,
                            "from_card": card, "from_alias": from_alias,
                        }
                        await ws.send_text(json.dumps({"type": "friend_request_sent", "request_id": request_id}))
                    else:
                        await ws.send_text(json.dumps({
                            "type": "error",
                            "message": "Usuário não está online. Compartilhe o código de contato por outro meio.",
                        }))

            elif msg_type == "friend_accept":
                if not my_user_id:
                    continue
                request_id = data.get("request_id")
                if not request_id or request_id not in pending_friend_requests:
                    continue
                req = pending_friend_requests[request_id]
                conn = db_connect()
                row = conn.execute("SELECT public_key, display_name FROM local_users WHERE user_id=?", (my_user_id,)).fetchone()
                conn.close()
                if row:
                    acceptor_pk = json.loads(row["public_key"])
                    acceptor_card = base64.b64encode(
                        json.dumps({"id": my_user_id, "publicKey": acceptor_pk}).encode()
                    ).decode()
                    acceptor_alias = row["display_name"] or my_user_id[:8]

                    # Try local delivery to sender
                    sender_ws = local_clients.get(req["from"])
                    if sender_ws:
                        await sender_ws.send_text(json.dumps({
                            "type": "friend_accepted", "request_id": request_id,
                            "user_id": my_user_id, "card": acceptor_card, "alias": acceptor_alias,
                        }))
                    else:
                        # Relay to peer
                        await relay_friend_response_to_peer(req["from"], {
                            "type": "peer_friend_accepted",
                            "request_id": request_id,
                            "user_id": my_user_id,
                            "card": acceptor_card,
                            "alias": acceptor_alias,
                            "origin_user": req["from"],
                        })

                    await ws.send_text(json.dumps({
                        "type": "friend_you_accepted", "request_id": request_id,
                        "user_id": req["from"], "card": req["from_card"], "alias": req["from_alias"],
                    }))
                pending_friend_requests.pop(request_id, None)

            elif msg_type == "friend_decline":
                if not my_user_id:
                    continue
                request_id = data.get("request_id")
                if not request_id or request_id not in pending_friend_requests:
                    continue
                req = pending_friend_requests.pop(request_id)
                sender_ws = local_clients.get(req["from"])
                if sender_ws:
                    await sender_ws.send_text(json.dumps({
                        "type": "friend_declined", "request_id": request_id, "user_id": my_user_id,
                    }))
                else:
                    await relay_friend_response_to_peer(req["from"], {
                        "type": "peer_friend_declined",
                        "request_id": request_id,
                        "user_id": my_user_id,
                        "origin_user": req["from"],
                    })

            elif msg_type == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))

            elif msg_type == "typing":
                if not my_user_id:
                    continue
                to_user = data.get("to")
                if not to_user:
                    continue
                # Deliver locally
                recipient_ws = local_clients.get(to_user)
                if recipient_ws:
                    await recipient_ws.send_text(json.dumps({
                        "type": "typing",
                        "from": my_user_id,
                        "to": to_user,
                        "alias": data.get("alias", my_user_id[:8]),
                    }))
                else:
                    # Relay to peer
                    await relay_event_to_peer(to_user, "peer_typing", {
                        "from": my_user_id,
                        "to": to_user,
                        "alias": data.get("alias", my_user_id[:8]),
                    })

            elif msg_type == "receipt":
                if not my_user_id:
                    continue
                envelope = data.get("envelope")
                receipt_type = data.get("receipt_type", "delivered")
                to_user = envelope.get("to") if envelope else None
                if not to_user:
                    continue
                # Deliver locally
                recipient_ws = local_clients.get(to_user)
                if recipient_ws:
                    await recipient_ws.send_text(json.dumps({
                        "type": "receipt",
                        "envelope": envelope,
                        "receipt_type": receipt_type,
                    }))
                else:
                    # Relay to peer
                    await relay_event_to_peer(to_user, "peer_receipt", {
                        "envelope": envelope,
                        "receipt_type": receipt_type,
                    })

            elif msg_type == "delete_account":
                if not my_user_id:
                    continue
                # Remove user from DB and memory
                conn = db_connect()
                conn.execute("DELETE FROM local_users WHERE user_id=?", (my_user_id,))
                conn.execute("DELETE FROM offline_queue WHERE user_id=?", (my_user_id,))
                conn.commit()
                conn.close()
                local_clients.pop(my_user_id, None)
                # Clean orphaned friend requests
                to_remove = [rid for rid, req in pending_friend_requests.items() if req.get("from") == my_user_id or req.get("to") == my_user_id]
                for rid in to_remove:
                    pending_friend_requests.pop(rid, None)
                # Notify peers
                await broadcast_peer_user_left(my_user_id)
                await ws.send_text(json.dumps({"type": "account_deleted"}))
                print(f"[no] User {my_user_id} deleted their account")
                my_user_id = None  # don't clean up again in finally
                try:
                    await ws.close()
                except Exception:
                    pass
                return

    except WebSocketDisconnect:
        pass
    finally:
        if my_user_id and local_clients.get(my_user_id) is ws:
            del local_clients[my_user_id]

# --------------------------------------------------------------------------
# WebSocket: federação (nó <-> nó)
# --------------------------------------------------------------------------

@app.websocket("/ws/peer")
async def peer_ws(ws: WebSocket):
    await ws.accept()
    remote_node_id = None
    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            if msg_type == "hello":
                remote_node_id = data.get("node_id")

                async def _send(text, _ws=ws):
                    await _ws.send_text(text)

                link = PeerLink(remote_node_id, _send)
                peer_connections[remote_node_id] = link
                print(f"[federacao] Nó vizinho conectado (entrada): {remote_node_id}")
                await ws.send_text(json.dumps({"type": "hello", "node_id": NODE_ID}))
                # Send our user list to the new peer
                await send_peer_users(link)

            elif msg_type == "peer_users":
                users = data.get("users", [])
                peer_users[remote_node_id] = users
                print(f"[federacao] Recebeu {len(users)} usuários do peer {remote_node_id}")

            elif msg_type == "peer_user_joined":
                user_id = data.get("user_id")
                display_name = data.get("display_name", "")
                if remote_node_id not in peer_users:
                    peer_users[remote_node_id] = []
                plist = peer_users[remote_node_id]
                if not any(u["user_id"] == user_id for u in plist):
                    plist.append({"user_id": user_id, "display_name": display_name})

            elif msg_type == "peer_friend_request":
                # Relay a friend request from a peer to a local user
                to_user = data.get("to")
                recipient_ws = local_clients.get(to_user)
                if recipient_ws:
                    await recipient_ws.send_text(json.dumps({
                        "type": "friend_request",
                        "request_id": data["request_id"],
                        "from": data["from"],
                        "from_alias": data["from_alias"],
                        "card": data["card"],
                    }))
                    # Store so we can relay the response back
                    pending_friend_requests[data["request_id"]] = {
                        "from": data["from"], "to": to_user,
                        "from_card": data["card"], "from_alias": data["from_alias"],
                    }

            elif msg_type == "peer_friend_accepted":
                # Relay accepted response back to local user
                target = data.get("origin_user")
                target_ws = local_clients.get(target)
                if target_ws:
                    await target_ws.send_text(json.dumps({
                        "type": "friend_accepted",
                        "request_id": data["request_id"],
                        "user_id": data["user_id"],
                        "card": data["card"],
                        "alias": data["alias"],
                    }))

            elif msg_type == "peer_friend_declined":
                target = data.get("origin_user")
                target_ws = local_clients.get(target)
                if target_ws:
                    await target_ws.send_text(json.dumps({
                        "type": "friend_declined",
                        "request_id": data["request_id"],
                        "user_id": data["user_id"],
                    }))

            elif msg_type == "relay":
                msg_id = data.get("msg_id")
                envelope = data.get("envelope")
                ttl = data.get("ttl", 0)
                if not msg_id or not envelope:
                    continue
                if not mark_seen(msg_id):
                    continue
                await route_envelope(envelope, msg_id, ttl, exclude_peer=remote_node_id)

            elif msg_type == "peer_typing":
                # Relay typing event from a peer to a local user
                to_user = data.get("to")
                recipient_ws = local_clients.get(to_user)
                if recipient_ws:
                    await recipient_ws.send_text(json.dumps({
                        "type": "typing",
                        "from": data.get("from"),
                        "to": to_user,
                        "alias": data.get("alias", ""),
                    }))

            elif msg_type == "peer_receipt":
                # Relay receipt event from a peer to a local user
                envelope = data.get("envelope")
                to_user = envelope.get("to") if envelope else None
                recipient_ws = local_clients.get(to_user) if to_user else None
                if recipient_ws:
                    await recipient_ws.send_text(json.dumps({
                        "type": "receipt",
                        "envelope": envelope,
                        "receipt_type": data.get("receipt_type", "delivered"),
                    }))

            elif msg_type == "peer_user_left":
                user_id = data.get("user_id")
                if user_id and remote_node_id in peer_users:
                    peer_users[remote_node_id] = [
                        u for u in peer_users[remote_node_id]
                        if u["user_id"] != user_id
                    ]
                    print(f"[federacao] Peer {remote_node_id} removed user {user_id}")

    except WebSocketDisconnect:
        pass
    finally:
        if remote_node_id:
            peer_connections.pop(remote_node_id, None)
            peer_users.pop(remote_node_id, None)
            print(f"[federacao] Nó vizinho desconectado: {remote_node_id}")

async def connect_to_peer(peer_url: str):
    while True:
        try:
            async with websockets.connect(peer_url) as ws:
                await ws.send(json.dumps({"type": "hello", "node_id": NODE_ID}))

                async def _send(text, _ws=ws):
                    await _ws.send(text)

                temp_id = f"pending:{peer_url}"
                link = PeerLink(temp_id, _send)
                peer_connections[temp_id] = link
                print(f"[federacao] Conectado ao nó vizinho: {peer_url}")

                async for raw in ws:
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if data.get("type") == "hello":
                        real_id = data.get("node_id")
                        peer_connections.pop(temp_id, None)
                        peer_connections[real_id] = link
                        link.node_id = real_id
                        temp_id = real_id
                        # Send our user list to the new peer
                        await send_peer_users(link)

                    elif data.get("type") == "peer_users":
                        users = data.get("users", [])
                        peer_users[temp_id] = users
                        print(f"[federacao] Recebeu {len(users)} usuários do peer {temp_id}")

                    elif data.get("type") == "peer_user_joined":
                        user_id = data.get("user_id")
                        display_name = data.get("display_name", "")
                        if temp_id not in peer_users:
                            peer_users[temp_id] = []
                        plist = peer_users[temp_id]
                        if not any(u["user_id"] == user_id for u in plist):
                            plist.append({"user_id": user_id, "display_name": display_name})

                    elif data.get("type") == "peer_friend_request":
                        to_user = data.get("to")
                        recipient_ws = local_clients.get(to_user)
                        if recipient_ws:
                            await recipient_ws.send_text(json.dumps({
                                "type": "friend_request",
                                "request_id": data["request_id"],
                                "from": data["from"],
                                "from_alias": data["from_alias"],
                                "card": data["card"],
                            }))
                            pending_friend_requests[data["request_id"]] = {
                                "from": data["from"], "to": to_user,
                                "from_card": data["card"], "from_alias": data["from_alias"],
                            }

                    elif data.get("type") == "peer_friend_accepted":
                        target = data.get("origin_user")
                        target_ws = local_clients.get(target)
                        if target_ws:
                            await target_ws.send_text(json.dumps({
                                "type": "friend_accepted",
                                "request_id": data["request_id"],
                                "user_id": data["user_id"],
                                "card": data["card"],
                                "alias": data["alias"],
                            }))

                    elif data.get("type") == "peer_friend_declined":
                        target = data.get("origin_user")
                        target_ws = local_clients.get(target)
                        if target_ws:
                            await target_ws.send_text(json.dumps({
                                "type": "friend_declined",
                                "request_id": data["request_id"],
                                "user_id": data["user_id"],
                            }))

                    elif data.get("type") == "relay":
                        msg_id = data.get("msg_id")
                        envelope = data.get("envelope")
                        ttl = data.get("ttl", 0)
                        if not msg_id or not envelope:
                            continue
                        if not mark_seen(msg_id):
                            continue
                        await route_envelope(envelope, msg_id, ttl, exclude_peer=temp_id)

                    elif data.get("type") == "peer_typing":
                        to_user = data.get("to")
                        recipient_ws = local_clients.get(to_user)
                        if recipient_ws:
                            await recipient_ws.send_text(json.dumps({
                                "type": "typing",
                                "from": data.get("from"),
                                "to": to_user,
                                "alias": data.get("alias", ""),
                            }))

                    elif data.get("type") == "peer_receipt":
                        envelope = data.get("envelope")
                        to_user = envelope.get("to") if envelope else None
                        recipient_ws = local_clients.get(to_user) if to_user else None
                        if recipient_ws:
                            await recipient_ws.send_text(json.dumps({
                                "type": "receipt",
                                "envelope": envelope,
                                "receipt_type": data.get("receipt_type", "delivered"),
                            }))

                    elif data.get("type") == "peer_user_left":
                        user_id = data.get("user_id")
                        if user_id and temp_id in peer_users:
                            peer_users[temp_id] = [
                                u for u in peer_users[temp_id]
                                if u["user_id"] != user_id
                            ]
                            print(f"[federacao] Peer {temp_id} removed user {user_id}")

        except Exception as e:
            print(f"[federacao] Falha ao conectar em {peer_url} ({e}). Tentando de novo em 5s...")
        finally:
            pending_urls.discard(peer_url)
            for key in list(peer_connections.keys()):
                if key.endswith(peer_url):
                    peer_connections.pop(key, None)
                    peer_users.pop(key, None)
        await asyncio.sleep(5)

@app.on_event("startup")
async def on_startup():
    init_db()
    print(f"[no] {NODE_ID} escutando na porta {PORT}")
    if PEER_URLS:
        print(f"[no] Conectando aos vizinhos: {PEER_URLS}")
    for url in PEER_URLS:
        asyncio.create_task(connect_to_peer(url))

    # Start UDP discovery if enabled
    if UDP_DISCOVER:
        asyncio.create_task(udp_broadcast_loop())
        asyncio.create_task(udp_listen_loop())
        asyncio.create_task(udp_cleanup_loop())

    async def periodic_cleanup():
        while True:
            await asyncio.sleep(60)
            cleanup_seen_messages()
    asyncio.create_task(periodic_cleanup())

# --------------------------------------------------------------------------
# Servir o frontend PWA
# --------------------------------------------------------------------------

WEB_DIR = os.environ.get("CHAT_WEB_DIR")
if not WEB_DIR:
    candidates = [
        os.path.join(os.path.dirname(BASE_DIR), "web"),
        os.path.join(BASE_DIR, "web"),
    ]
    WEB_DIR = next((c for c in candidates if os.path.isfile(os.path.join(c, "index.html"))), None)

if WEB_DIR:
    print(f"[web] Servindo frontend de: {WEB_DIR}")

    @app.get("/")
    def index():
        return FileResponse(os.path.join(WEB_DIR, "index.html"))

    app.mount("/", StaticFiles(directory=WEB_DIR), name="web")
else:
    print("[web] AVISO: pasta 'web/' não encontrada. Servindo apenas a API/WebSocket.")

# --------------------------------------------------------------------------

def main():
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")

if __name__ == "__main__":
    main()
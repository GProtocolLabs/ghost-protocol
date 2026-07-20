# GHOST Federation

## Overview

GHOST PROTOCOL federation allows multiple independent nodes to connect and form a unified messaging network. There is no central server — the network is a graph of nodes that establish bilateral WebSocket connections and relay messages between their local users.

## Federation Model

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Node A     │◄───►│   Node B     │◄───►│   Node C     │
│  (port 8000) │     │  (port 8001) │     │  (port 8002) │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
   ┌───┴───┐            ┌───┴───┐            ┌───┴───┐
   │ Users │            │ Users │            │ Users │
   │A1..An │            │B1..Bn │            │C1..Cn │
   └───────┘            └───────┘            └───────┘
```

### Principles

1. **Node sovereignty:** Each node manages its own users and policies
2. **Explicit peering:** Federation requires a direct WebSocket connection between nodes
3. **Transitive relay:** A user on Node A can reach a user on Node C via Node B
4. **Blind relay:** Intermediate nodes cannot read message content (E2EE)
5. **Federated user discovery:** Peer nodes share their user lists

## Node Architecture

### Components

```
┌──────────────────────────────────────────────────┐
│                  Node Server                      │
│                                                    │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ Client WS│  │ Storage  │  │ Peer WS       │   │
│  │ (/ws/    │  │ (SQLite) │  │ (/ws/peer)    │   │
│  │  client) │  │          │  │               │   │
│  └──────────┘  └──────────┘  └───────────────┘   │
│                                                    │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ REST API │  │ PWA      │  │ Message       │   │
│  │ (/api/*) │  │ Static   │  │ Router        │   │
│  └──────────┘  └──────────┘  └───────────────┘   │
└──────────────────────────────────────────────────┘
```

### Node Storage

The node stores only:

| Data | Retention | Purpose |
|------|-----------|---------|
| User public keys | While registered | Identity lookup |
| Undelivered messages | Until delivery | Store-and-forward for offline users |
| Seen message IDs | 5 minutes | Deduplication |

The node does NOT store:
- Private keys (never leave the client)
- Decrypted message content (impossible: E2EE)
- Message history beyond offline queue

## Federation Protocol

### Peer Handshake

Two nodes establish a federation link via WebSocket at `/ws/peer`:

```
Node A                                            Node B
  |                                                 |
  |-- WS connect to /ws/peer ---------------------> |
  |-- {"type":"hello", "node_id":"node-abc123"} --> |
  |<-- {"type":"hello", "node_id":"node-xyz789"} --- |
  |                                                 |
  |<-- {"type":"peer_users", "users": [...]} ------- |
  |-- {"type":"peer_users", "users": [...]} ------->|
  |                                                 |
  |  [Federation active — messages can be relayed]   |
```

### Connecting to Peers

Nodes can connect to peers in two ways:

1. **Startup configuration:** Pass `--peers ws://other-node:8000/ws/peer` as a CLI argument or set the `PEERS` environment variable (comma-separated).
2. **On-demand:** POST to `/api/connect` with `{"url": "ws://other-node:8000/ws/peer"}`.

If a peer connection drops, the node automatically retries every 5 seconds.

### Node Identification

Each node has a unique ID. If not provided via `--node-id` or the `NODE_ID` environment variable, a random ID is generated (`node-` + 8 hex characters).

### User List Sharing

When a peer connection is established, each node sends its full user list to the other. When a new user registers on a node, a `peer_user_joined` notification is broadcast to all connected peers.

## Message Relay

### TTL-Based Routing

Messages relayed between nodes use a Time-To-Live (TTL) counter to prevent infinite loops:

```
Envelope arrives at Node A (TTL=6)
  → Recipient not local
  → TTL > 0: relay to all peers except the origin (TTL=5)
    → Node B receives relay
      → Recipient is local on Node B: deliver
```

### Deduplication

Each relayed message has a unique `msg_id`. Nodes track seen message IDs in a SQLite table with a 5-minute expiry. Already-seen messages are silently dropped.

### Friend Requests Across Nodes

Friend requests are relayed between nodes:

```
Alice (Node A) ── friend_request(to: Bob) ──► Node A
  → Bob is not local on Node A
  → Node A checks peer_users on Node B: Bob is there
  → Node A sends peer_friend_request to Node B
    → Node B delivers friend_request to Bob
    → Bob accepts → Node B sends peer_friend_accepted back to Node A
      → Node A delivers friend_accepted to Alice
```

## Network Discovery

### REST API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/status` | Node status: node_id, port, user count, connected peers |
| `/api/network` | Full network map with all nodes and their users |
| `/api/peers` | Detailed peer list with user counts |
| `/api/local-users` | All discoverable users (local + peer users) |
| `/api/connect` | Connect to a new peer on demand |

### Client-Side Network View

The web client (PWA) displays a network panel showing:
- This node and all connected peers
- Users on each node with their display names
- Ability to add users from any node as contacts (triggers friend request relay)

## Node Configuration

### CLI Arguments

| Argument | Env Variable | Default | Description |
|----------|-------------|---------|-------------|
| `--port` | `PORT` | `8000` | HTTP/WebSocket port |
| `--node-id` | `NODE_ID` | auto-generated | Unique node identifier |
| `--peers` | `PEERS` | (none) | Comma-separated peer URLs |
| `--db` | `NODE_DB` | `node_{port}.db` | SQLite database path |

### Starting a Node

```bash
# Standalone node
python server/app.py --port 8000

# Federated node
python server/app.py --port 8001 --peers ws://localhost:8000/ws/peer

# Multiple peers
python server/app.py --port 8002 --peers ws://localhost:8000/ws/peer,ws://localhost:8001/ws/peer
```

### Multi-Node Topology

```
Terminal 1: python server/app.py --port 8000
Terminal 2: python server/app.py --port 8001 --peers ws://localhost:8000/ws/peer
Terminal 3: python server/app.py --port 8002 --peers ws://localhost:8000/ws/peer,ws://localhost:8001/ws/peer
```

## Client-Side Peer Management

The web client includes a network panel accessible from the main chat screen that allows:

1. Viewing all connected nodes, their users, and connection status
2. Connecting to new peers by entering a WebSocket URL
3. Adding users from any federated node as contacts

## Limitations (Current Version)

- No authentication between peers (open WebSocket)
- No TLS/encryption on the wire between nodes (messages are E2EE but metadata is visible)
- No rate limiting between peers
- No peer reputation or trust system
- Maximum 6 relay hops (TTL-based)
- Peer connections are bidirectional but there is no mesh topology optimization (full mesh for configured peers)

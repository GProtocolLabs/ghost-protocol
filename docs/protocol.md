# GHOST Protocol

## Overview

GHOST PROTOCOL is a peer-to-peer encrypted messaging system built on WebSocket with optional federated relay nodes. Messages are end-to-end encrypted using ECDH key agreement and routed through a network of relay servers (nodes) that can optionally federate with each other. The name reflects the philosophy: messages that leave no traces — once delivered, they disappear from intermediate infrastructure.

## Protocol Stack

```
+----------------------------------+
|       Application Layer          |
|   (messages, friend requests)    |
+----------------------------------+
|       Routing Layer              |
|   (TTL-based relay + peers)      |
+----------------------------------+
|       Session Layer              |
|   (ECDH P-256 + AES-GCM)        |
+----------------------------------+
|       Transport Layer            |
|   (WebSocket / HTTP REST)        |
+----------------------------------+
```

## Message Format

All messages use JSON over WebSocket with the following envelope structure:

```json
{
  "to": "<recipient-user-id>",
  "from": "<sender-user-id>",
  "iv": "<base64-encoded-aes-gcm-iv>",
  "ciphertext": "<base64-encoded-aes-gcm-ciphertext>",
  "ts": 1752951600000,
  "msg_id": "<uuid>"
}
```

### Message Types (WebSocket)

| Type | Description |
|------|-------------|
| `register` | Client registers with the node, providing user_id, public_key, display_name |
| `registered` | Server confirmation of registration |
| `send` | Send an encrypted message envelope to a recipient |
| `message` | Incoming encrypted message delivered to recipient |
| `friend_request` | Request to add a contact |
| `friend_request_sent` | Confirmation that a friend request was queued |
| `friend_accept` | Accept a pending friend request |
| `friend_decline` | Decline a pending friend request |
| `friend_accepted` | Notification that a sent request was accepted |
| `friend_you_accepted` | Confirmation that you accepted a request (includes contact card) |
| `ping` / `pong` | Connection keep-alive |

### Peer-to-Node Message Types

| Type | Description |
|------|-------------|
| `hello` | Peer handshake with node_id |
| `relay` | Relay a message envelope to another node (with TTL) |
| `peer_users` | Exchange list of registered users between nodes |
| `peer_user_joined` | Notify peer that a new user registered |
| `peer_friend_request` | Relay a friend request to a peer node |
| `peer_friend_accepted` | Relay an accepted friend request response |
| `peer_friend_declined` | Relay a declined friend request response |

## Message Routing

### Local Delivery

When a message's recipient is registered on the same node, the message is delivered directly via the recipient's active WebSocket connection.

### Offline Queue

If the recipient is not currently connected, the encrypted envelope is stored in the node's SQLite database and delivered when the recipient reconnects and sends a `register` message.

### Relay via Peers

When the recipient is on a different node (federated peer), the message is relayed through the WebSocket peer connection with a TTL (Time-To-Live) counter. Each hop decrements the TTL until it reaches 0.

```
Alice ──► Node A ──► Node B ──► Bob
         (local)  (peer WS) (local)
```

### Deduplication

Each message has a unique `msg_id`. Nodes track seen message IDs (with a 5-minute expiry) to prevent duplicate delivery across multiple relay paths.

## Connection Flow

```
Client                        Node                        Peer Node
  |                            |                            |
  |-- register(user_id, pk) -> |                            |
  |<- registered(node_id) ---- |                            |
  |                            |                            |
  |                            |<== hello (peer WS) =======>|
  |                            |<== peer_users exchange ==> |
  |                            |                            |
  |-- send(envelope to:Bob) -> |                            |
  |                            |--- relay(envelope) ------>|
  |                            |                            |---> Bob (local)
  |                            |<--- (Bob replies) --------|
  |<- message(envelope) ------ |                            |
```

## Connection Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MAX_TTL` | 6 | Maximum relay hops for messages |
| `SEEN_MSG_EXPIRY` | 300s | How long to track seen message IDs |
| `offline_queue_retention` | Until delivery | Messages stored until recipient reconnects |

## REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Node status (node_id, port, user count, connected peers) |
| `/api/lookup/{user_id}` | GET | Look up a user's public key |
| `/api/network` | GET | Network map: all nodes and their users |
| `/api/connect` | POST | Connect to a peer node on demand (body: `{"url": "ws://..."}`) |
| `/api/peers` | GET | Detailed peer list with user counts |
| `/api/local-users` | GET | All users visible on this node (local + peer users) |

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1 | 2026-06 | Initial protocol: JSON/WebSocket, ECDH P-256 + AES-GCM, TTL-based relay, friend request system |

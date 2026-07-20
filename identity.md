# GHOST Identity

## Philosophy

In GHOST PROTOCOL, identity is sovereignty. There is no central server, mandatory email, or phone number. Your private key is your digital identity — you generate it locally, back it up yourself, and no one can recover it for you if lost.

## Identity Model

```
┌─────────────────────────────────────────┐
│           Identity Key Pair             │
│           (ECDH P-256)                  │
├─────────────────────────────────────────┤
│  ┌───────────────┐  ┌────────────────┐  │
│  │   User ID     │  │  Display Name  │  │
│  │ (derived from │  │  (user-chosen) │  │
│  │  public key)  │  │                │  │
│  └───────────────┘  └────────────────┘  │
├─────────────────────────────────────────┤
│  ┌───────────────┐  ┌────────────────┐  │
│  │  IndexedDB    │  │  Backup String │  │
│  │  (local store)│  │  (base64 JSON) │  │
│  └───────────────┘  └────────────────┘  │
└─────────────────────────────────────────┘
```

## User ID

### Format

```
<22-char-base64url-string>
```

Example:
```
8xM2vFp9qR4kT7yW3nL6bH1
```

### Derivation

```
user_id = base64url(SHA256(canonical_json(public_key_jwk)))[0:22]
```

The public key is serialized as a canonical JWK (JSON Web Key) with fields `kty`, `crv`, `x`, `y`. This JSON string is hashed with SHA-256, and the first 22 characters of the base64url-encoded hash form the user ID.

This provides ~131 bits of collision resistance (22 × 6 bits for base64url), sufficient for unique identification within the network.

## Display Name

Users choose a display name during initial setup. Unlike the user ID, the display name:

- Is not cryptographically bound to the identity
- Can be changed at any time via settings
- Is shared with peers when you register on a node
- Is shown to other users in the network panel and friend requests

## Key Generation

### Algorithm

- **Curve:** NIST P-256 (secp256r1)
- **API:** Web Crypto API (`SubtleCrypto`)
- **Method:** `crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" })`
- **Usages:** `deriveKey`, `deriveBits`

### Creation Flow

```
User clicks "Create Identity"
  → Browser generates ECDH P-256 key pair
  → User ID derived from public key
  → Backup string generated (base64 JSON)
  → User prompted to save backup
  → User sets display name
  → Identity stored in IndexedDB
  → WebSocket connection to node established
```

## Identity Restoration

### Backup Format

The backup is a base64-encoded JSON string:

```json
{
  "userId": "8xM2vFp9qR4kT7yW3nL6bH1",
  "publicKeyJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  },
  "privateKeyJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>",
    "d": "<base64url>"
  }
}
```

### Restoration Flow

```
User clicks "Restore Identity"
  → Pastes backup string
  → Client decodes base64 → parses JSON
  → Validates: derive user_id from publicKeyJwk matches stored userId
  → Imports private key via Web Crypto API
  → Sets display name (or restores existing name)
  → Connects to node
```

Validation ensures the backup hasn't been corrupted or tampered with — if the derived user ID doesn't match the stored one, restoration is rejected.

## Contact Cards

Contact cards are how users share their identity with others:

### Format

```json
{
  "id": "<user-id>",
  "publicKey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  }
}
```

### Transport

Contact cards are base64-encoded and can be shared via:

1. **QR Code:** Displayed on screen, scannable by another user's device camera
2. **Clipboard:** Copied as text and pasted into the "Add Contact" dialog
3. **Friend Request:** Embedded in friend request messages sent through the node network
4. **Manual entry:** Pasted into the "Paste code" tab of the Add Contact modal

### Verification

When adding a contact via card, the client:

1. Decodes the base64 card
2. Derives the user ID from the embedded public key
3. Validates that the derived ID matches the `id` field
4. Rejects cards where the ID doesn't match (tampered or corrupted)

## Friend Request System

### Flow

```
Alice                                          Bob
  |                                             |
  |-- friend_request(to: Bob, card: Alice) ---> |
  |                                             |
  |           Bob sees toast: "Alice wants to   |
  |           add you as a contact"             |
  |                                             |
  |           [Accept]         [Decline]         |
  |              |                 |            |
  |<-- accepted  |                 |-- declined |
  |   (card: Bob)|                             |
  |                                             |
  |  Both parties now have each other's         |
  |  public keys and can exchange messages      |
```

### Multi-Node Friend Requests

Friend requests are relayed across federated nodes. If Alice and Bob are on different nodes, the request is routed through the peer WebSocket connections and delivered to Bob's node.

### Local-Only Discovery

If Bob is not online on any known node when Alice sends a friend request, the request fails. Alice is prompted to share her contact card through an out-of-band channel (messaging app, email, QR code in person).

## Storage

All identity data is stored locally in the browser using IndexedDB:

| Store | Key | Content |
|-------|-----|---------|
| `identity` | `"me"` | userId, name, publicKeyJwk, privateKeyJwk |
| `contacts` | contact ID | id, alias (display name), publicKeyJwk |
| `messages` | msgId | roomId, from, to, plaintext, ts, mine |
| `friend_requests` | requestId | from, from_alias, card, ts |

### Security Notes

- Private keys are stored in IndexedDB as JWK JSON (not encrypted at the application layer; browser provides OS-level encryption where available)
- No data is ever sent to the node unencrypted (message content is AES-GCM encrypted)
- Contact public keys are stored and used to derive per-contact AES keys
- Clearing browser data or uninstalling the PWA deletes the identity permanently

## Identity Lifecycle

### Creation

`Create Identity` → Key generation → Backup → Name setup → Ready

### Active Use

Connect to node → Register → Exchange messages via E2EE

### Migration

1. Export backup string from Settings (or copy from initial setup)
2. On new device/browser, use "Restore Identity" with the backup string
3. Message history is NOT transferred (each device starts fresh)
4. Contacts must be re-added (contact information is not in the backup)

### Deletion

Use the "Logout" button in Settings. This:
1. Clears all IndexedDB stores (identity, contacts, messages, friend requests)
2. Closes the WebSocket connection
3. Reloads the page, returning to the identity creation screen

There is no server-side deletion — once the node's offline queue expires, no trace of the identity remains on the network.

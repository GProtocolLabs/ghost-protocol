# GHOST Encryption

## Principles

All communication on GHOST PROTOCOL is end-to-end encrypted (E2EE) by default. There is no plaintext mode. Not even federated relay nodes have access to message content.

## Cryptographic Architecture

```
+------------------------------------------------------------------+
|                    AES-256-GCM (AEAD)                            |
|                 Symmetric content encryption                     |
+------------------------------------------------------------------+
|                    ECDH Key Agreement                            |
|                 P-256 curve (Web Crypto API)                     |
+------------------------------------------------------------------+
|                    SHA-256                                       |
|            Key fingerprint derivation                            |
+------------------------------------------------------------------+
```

## Cryptographic Identity

Each user (ghost) has a key pair:

| Key | Algorithm | Use |
|-----|-----------|-----|
| Identity Key Pair | ECDH P-256 | Key agreement + identity |

### User ID

The user ID is derived from the public key:

```
user_id = base64url(SHA256(canonical_public_key_jwk))[0:22]
```

The public key JWK is serialized in canonical JSON form and hashed with SHA-256. The resulting hash is base64url-encoded and truncated to 22 characters. This provides a compact, human-usable identifier that is cryptographically bound to the key pair.

## ECDH Key Agreement

When two users want to communicate, they derive a shared AES key:

```
Alice                                                      Bob
  |                                                         |
  |-- Contact Card (public_key_jwk) ----------------------> |
  |                                                         |
  |  shared_key = ECDH(alice_private, bob_public)           |
  |                                                         |
  |                              shared_key = ECDH(bob_private, alice_public)
  |                                                         |
  |<=========== AES-256-GCM communication =================>|
```

### Contact Card Format

Contact cards are exchanged via friend requests or QR codes:

```json
{
  "id": "<user_id>",
  "publicKey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url-x-coordinate>",
    "y": "<base64url-y-coordinate>"
  }
}
```

Cards are base64-encoded for transport via QR code, clipboard paste, or friend request messages.

### Key Derivation

The shared AES-256-GCM key is derived from the ECDH operation using the P-256 curve. The Web Crypto API's `deriveKey` method is used with:

- **Algorithm:** ECDH
- **Named curve:** P-256
- **Derived key:** AES-GCM, 256-bit
- **Usages:** encrypt, decrypt

### Shared Key Caching

Derived AES keys are cached in memory for the duration of the session (per-contact). This avoids re-deriving the key for every message while keeping the keys ephemeral (lost on page reload or tab close).

## Message Encryption

### Algorithm

- **Cipher:** AES-256-GCM (AEAD)
- **IV:** 12 random bytes per message
- **Key:** Derived via ECDH P-256 from the sender's private key and recipient's public key

### Ciphertext Format

Each message envelope contains:

```json
{
  "to": "<recipient-id>",
  "from": "<sender-id>",
  "iv": "<base64-12-byte-iv>",
  "ciphertext": "<base64-aes-gcm-output>",
  "ts": 1752951600000,
  "msg_id": "<uuid>"
}
```

### Reply Messages

When replying to a specific message, the plaintext is structured as JSON:

```json
{
  "text": "my reply message",
  "replyTo": "<original-msg-id>"
}
```

This is encrypted alongside the message text and decoded on the recipient side to show a reply preview.

## Key Management

### Backup and Restoration

The identity key pair can be exported as a base64-encoded JSON string containing:

```json
{
  "userId": "<user-id>",
  "publicKeyJwk": { ... },
  "privateKeyJwk": { ... }
}
```

This backup string is the only way to recover an identity. If lost, the identity is permanently unrecoverable.

### Storage

- **Identity key pair:** Stored in IndexedDB (browser PWA)
- **Contact public keys:** Stored in IndexedDB alongside contact metadata
- **Message history:** Stored in IndexedDB, encrypted at rest by the browser
- **Shared AES keys:** Memory only (not persisted)

### Key Rotation

There is no automatic key rotation in the current version. Users can create a new identity at any time, which generates a new key pair and a new user ID.

## Security Considerations

- **Forward secrecy:** Not provided in the current implementation (single static key pair per identity)
- **Key compromise:** If a private key is compromised, all past and future messages for that identity are compromised
- **Trust on first use (TOFU):** Contact public keys are accepted on first exchange via the friend request system
- **No key verification:** There is no safety number or out-of-band key verification in the current version

## Reference Implementation

- **Browser:** Web Crypto API (SubtleCrypto), implemented in `web/app.js`
- **Node server:** No cryptographic operations — the server is a blind relay
- **Key exchange:** ECDH P-256 via `crypto.subtle.deriveKey`
- **Encryption:** AES-256-GCM via `crypto.subtle.encrypt` / `crypto.subtle.decrypt`

# Ghost Protocol

> **An open-source federated communication protocol with end-to-end encryption and cryptographic identities.**

Ghost Protocol is an experimental communication protocol focused on privacy, decentralization and user ownership.

Instead of relying on centralized accounts, passwords, phone numbers or email addresses, every user owns a cryptographic identity generated locally in the browser.

Nodes automatically discover each other on the local network and form a federated network. They only relay encrypted packets and **cannot read message contents**.

> 🚧 **Status:** Alpha (Proof of Concept)

---

## ✨ Features

- 🔐 End-to-End Encryption (ECDH P-256 + AES-GCM)
- 🔑 Cryptographic identities
- 🌐 Federated nodes
- 🔍 Automatic peer discovery (LAN)
- 💬 Offline encrypted message queue
- 📱 Progressive Web App (PWA)
- 🚫 No passwords
- 🚫 No phone numbers
- 🚫 No email accounts
- 🛡️ Public-key based identity

---

## ✅ Current Features

- Deterministic identity generation
- Public-key derived user ID
- End-to-end encrypted messaging
- Automatic node discovery on local networks
- Federation between multiple nodes
- Cross-node encrypted routing
- Offline message delivery
- Friend requests
- Identity backup and restore

---

## 📂 Project Structure

```text
ghost-protocol/
│
├── server/
│   ├── app.py
│   ├── node_server.py
│   └── requirements.txt
│
└── web/
    ├── index.html
    ├── app.js
    ├── style.css
    ├── manifest.json
    └── sw.js
```

---

## 🚀 Quick Start

Clone the repository:

```bash
git clone https://github.com/GProtocolLabs/ghost-protocol.git
```

Start a node:

```bash
cd server
python app.py --port 8000
```

Open your browser:

```
http://localhost:8000
```

Create a new identity.

If another Ghost node is running on the same local network, both nodes will automatically discover each other and join the same federated network.

No manual peer configuration is required.

---

## 🏗 Architecture

```text
┌─────────────┐
│  Browser    │
└──────┬──────┘
       │
Generate Key Pair
       │
User ID = SHA-256(Public Key)
       │
Encrypted Messages
       │
┌─────────────┐
│ Ghost Node  │
└──────┬──────┘
       │
══════════════════════════════
       │
┌─────────────┐
│ Ghost Node  │
└──────┬──────┘
       │
══════════════════════════════
       │
┌─────────────┐
│ Ghost Node  │
└─────────────┘
```

Nodes never own user accounts.

Nodes never store passwords.

Nodes only relay encrypted packets.

---

## 🔒 Security

### Identity

- ECDH P-256 key pair
- Generated locally inside the browser
- Stored in IndexedDB
- User ID = SHA-256(Public Key)

### Backup

Users can export their private key.

Without the private key, the identity cannot be recovered.

Ghost Protocol follows a self-custody model similar to cryptocurrency wallets.

### Encryption

Every message uses:

- ECDH shared secret
- AES-256-GCM
- Random IV

Only the intended recipient can decrypt the message.

### What Nodes Can See

Nodes can only see:

- Sender ID
- Recipient ID
- Timestamp

Nodes **cannot** access:

- Message contents
- Private keys
- User passwords

---

## ⚠ Known Limitations

Ghost Protocol is currently an Alpha implementation.

Current limitations include:

- Metadata is not protected.
- Identity registration is not signed.
- No Perfect Forward Secrecy.
- No NAT traversal.
- No multi-device synchronization.
- Home-node migration is not implemented.
- Routing currently uses Flood + TTL.

---

## 🗺 Roadmap

- ✅ Cryptographic identities
- ✅ End-to-end encryption
- ✅ Automatic LAN discovery
- ✅ Federated nodes
- ✅ Friend requests
- ✅ Offline messages
- ⬜ Signed identity registration
- ⬜ Perfect Forward Secrecy
- ⬜ Group conversations
- ⬜ File transfer
- ⬜ Voice calls
- ⬜ Video calls
- ⬜ Mobile applications
- ⬜ Distributed routing (DHT)

---

## 💡 Philosophy

Ghost Protocol is built around a simple principle.

> Users should own their identity.
>
> Servers should relay messages — not own accounts.
>
> Privacy should be the default.
>
> Open protocols build a freer digital world.

---

## 🤝 Contributing

Contributions are welcome.

You can help by:

- Reporting bugs
- Improving documentation
- Reviewing security
- Optimizing performance
- Developing new features
- Improving the protocol

Pull Requests and Issues are always welcome.

---

## 📄 License

Released under the MIT License.

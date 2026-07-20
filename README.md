Ghost Protocol

An open-source federated communication protocol with end-to-end encryption and cryptographic identities.

Ghost Protocol is an experimental communication protocol focused on privacy, decentralization and user ownership.

Instead of relying on centralized servers, passwords, phone numbers or email addresses, every user owns a cryptographic identity generated locally in the browser. Nodes automatically discover each other on the local network and form a federated communication network. Nodes only relay encrypted packets—they cannot read message contents.

🚧 Current Status: Alpha / Proof of Concept

Features
🔐 End-to-End Encryption (ECDH P-256 + AES-GCM)
🔑 Cryptographic Identity (no passwords)
🌐 Federated Nodes
🔍 Automatic Peer Discovery (Local Network)
💬 Offline Encrypted Message Queue
📱 Progressive Web App (PWA)
🚫 No Central Account Server
🛡️ Public-Key Based Identity
🔄 Automatic Node Federation
Tested
✅ Deterministic identity generation from the public key
✅ End-to-end encrypted messaging
✅ Automatic node discovery on the local network
✅ Federation between multiple nodes
✅ Cross-node encrypted message routing
✅ Offline encrypted message delivery
✅ Friend requests between users
✅ Local identity backup and restore
Project Structure
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
Quick Start

Clone the repository:

git clone https://github.com/GProtocolLabs/ghost-protocol.git

Start a node:

cd server
python app.py --port 8000

Open:

http://localhost:8000

Create your cryptographic identity.

If another Ghost node is running on the same local network, both nodes will automatically discover each other and join the same federated network.

No manual peer configuration is required.

How It Works

Every user generates a cryptographic identity locally.

Browser
    │
Generate Key Pair
    │
User ID = SHA-256(Public Key)
    │
Encrypted Messages
    │
Ghost Node
    │
════════════════════════════
    │
Ghost Node
    │
════════════════════════════
    │
Ghost Node

Nodes never own user accounts.

Nodes never store passwords.

Nodes never decrypt messages.

They simply relay encrypted packets across the federation.

Security
Identity
ECDH P-256 key pair
Generated locally inside the browser
Stored in IndexedDB
User ID derived from SHA-256 of the public key
Backup

The private key can be exported as a backup.

Without the private key, the identity cannot be recovered.

Ghost Protocol follows the self-custody model.

Encryption

Each message is encrypted using:

ECDH shared secret
AES-256-GCM
Random IV per message

Only the intended recipient can decrypt the message.

What Nodes Can See

Nodes only know:

Sender ID
Recipient ID
Timestamp

Nodes cannot access:

Message contents
Private keys
User passwords (none exist)
Current Limitations

This is still an Alpha implementation.

Current limitations include:

Metadata is not yet protected.
Identity registration is not signed.
No Perfect Forward Secrecy.
No NAT traversal.
No multi-device synchronization.
Home node migration is not implemented.
Routing currently uses flood + TTL.
Roadmap
✅ Cryptographic identities
✅ End-to-end encryption
✅ Federated nodes
✅ Automatic LAN discovery
✅ Friend requests
✅ Offline messages
⬜ Signed identity registration
⬜ Perfect Forward Secrecy
⬜ Group conversations
⬜ File transfer
⬜ Voice calls
⬜ Video calls
⬜ Mobile applications
⬜ Distributed routing (DHT)
Philosophy

Ghost Protocol is built around a simple principle:

Users should own their identity.

Servers should relay messages—not own accounts.

Privacy should be the default.

Open protocols build a freer digital world.

Contributing

Contributions are welcome.

You can help by:

Reporting bugs
Improving documentation
Reviewing security
Optimizing performance
Developing new features
Improving the protocol specification

Feel free to open Issues or submit Pull Requests.

License

MIT License

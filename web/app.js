/*
 * Ghost Protocol
 * Copyright (c) 2026 GProtocolLabs
 *
 * Licensed under the MIT License.
 * See LICENSE file in the project root.
 *
 * https://github.com/GProtocolLabs/ghost-protocol
 */

// =======================================================================
// Chat P2P — Frontend PWA
// Features: E2E encryption, digital signatures, encrypted file transfer,
//           QR code add, friend requests, local network discovery,
//           reply-to-message, delete conversation, delete message
// =======================================================================

const DEFAULT_NODE_WS = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/client";

// =======================================================================
// Criptografia (Web Crypto API)
// =======================================================================

const Crypto = {
  // --- Identity: ECDH P-256 for shared-secret encryption ---

  async generateIdentityKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
  },

  async generateSigningKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
  },

  async exportPublicKeyJwk(publicKey) {
    const jwk = await crypto.subtle.exportKey("jwk", publicKey);
    return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  },

  async exportPrivateKeyJwk(privateKey) {
    return crypto.subtle.exportKey("jwk", privateKey);
  },

  async importPublicKeyJwk(jwk) {
    return crypto.subtle.importKey("jwk", { ...jwk, ext: true }, { name: "ECDH", namedCurve: "P-256" }, true, []);
  },

  async importPrivateKeyJwk(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
  },

  async importSignPublicKeyJwk(jwk) {
    return crypto.subtle.importKey("jwk", { ...jwk, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  },

  async importSignPrivateKeyJwk(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  },

  async deriveUserId(publicKeyJwkCanonical) {
    const bytes = new TextEncoder().encode(JSON.stringify(publicKeyJwkCanonical));
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return b64url(new Uint8Array(hash)).slice(0, 22);
  },

  async deriveSharedAesKey(myPrivateKey, theirPublicKey) {
    return crypto.subtle.deriveKey(
      { name: "ECDH", public: theirPublicKey },
      myPrivateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  async encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, data);
    return { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
  },

  async encryptBytes(aesKey, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, bytes);
    return { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
  },

  async decrypt(aesKey, ivB64, ciphertextB64) {
    const iv = unb64(ivB64);
    const ciphertext = unb64(ciphertextB64);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
    return new TextDecoder().decode(plainBuf);
  },

  async decryptBytes(aesKey, ivB64, ciphertextB64) {
    const iv = unb64(ivB64);
    const ciphertext = unb64(ciphertextB64);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
  },

  // --- Digital Signatures: ECDSA P-256 ---

  async sign(signingPrivateKey, data) {
    const bytes = new TextEncoder().encode(data);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingPrivateKey, bytes);
    return b64(new Uint8Array(sig));
  },

  async verify(signingPublicKey, signatureB64, data) {
    const sig = unb64(signatureB64);
    const bytes = new TextEncoder().encode(data);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signingPublicKey, sig, bytes);
  },

  // --- File encryption ---

  async encryptFile(aesKey, file) {
    const arrayBuffer = await file.arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, arrayBuffer);
    return { iv: b64(iv), ciphertext: b64(new Uint8Array(cipherBuf)) };
  },

  async decryptFile(aesKey, ivB64, ciphertextB64) {
    const iv = unb64(ivB64);
    const cipherBuf = unb64(ciphertextB64);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, cipherBuf);
  },
};

function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(str) { return Uint8Array.from(atob(str), (c) => c.charCodeAt(0)); }
function b64url(bytes) { return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function arrayBufferToBase64(buffer) {
  return b64(new Uint8Array(buffer));
}

// =======================================================================
// Armazenamento local (IndexedDB) — v3
// =======================================================================

const Store = {
  db: null,

  async open() {
    if (this.db) return this.db;
    this.db = await new Promise((resolve, reject) => {
      const req = indexedDB.open("chat-p2p", 4);
      req.onupgradeneeded = (e) => {
        const db = req.result;
        if (!db.objectStoreNames.contains("identity")) db.createObjectStore("identity");
        if (!db.objectStoreNames.contains("contacts")) db.createObjectStore("contacts", { keyPath: "id" });
        if (!db.objectStoreNames.contains("messages")) {
          const store = db.createObjectStore("messages", { keyPath: "msgId" });
          store.createIndex("roomId", "roomId");
        } else {
          // Ensure index exists on upgrade
          const store = e.target.transaction.objectStore("messages");
          if (!store.indexNames.contains("roomId")) {
            store.createIndex("roomId", "roomId");
          }
        }
        if (!db.objectStoreNames.contains("friend_requests")) {
          db.createObjectStore("friend_requests", { keyPath: "requestId" });
        }
        if (!db.objectStoreNames.contains("file_chunks")) {
          db.createObjectStore("file_chunks", { keyPath: "chunkId" });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this.db;
  },

  async get(storeName, key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const req = tx.objectStore(storeName).get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  },

  async put(storeName, value, key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const req = key !== undefined ? tx.objectStore(storeName).put(value, key) : tx.objectStore(storeName).put(value);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  },

  async delete(storeName, key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const req = tx.objectStore(storeName).delete(key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  },

  async getAll(storeName) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const req = tx.objectStore(storeName).getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  },

  async getByIndex(storeName, indexName, value) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      const req = tx.objectStore(storeName).index(indexName).getAll(value);
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  },

  async clearAll() {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(["identity", "contacts", "messages", "friend_requests", "file_chunks"], "readwrite");
      tx.objectStore("identity").clear();
      tx.objectStore("contacts").clear();
      tx.objectStore("messages").clear();
      tx.objectStore("friend_requests").clear();
      tx.objectStore("file_chunks").clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
};

// =======================================================================
// Estado da aplicação
// =======================================================================

let me = null;          // { userId, name, privateKey, signPrivateKey, publicKeyJwk, signPublicKeyJwk }
let ws = null;
let wsReady = false;
let currentContact = null;
let replyTarget = null;
let pendingFriendRequests = [];
let qrScanner = null;
let activeFileTransfers = {};
let typingTimer = null;
let lastTypingSent = 0;
let reactionPickerMsgId = null;
const TYPING_COOLDOWN = 3000; // ms between typing events

const sharedKeyCache = new Map();

// =======================================================================
// Theme
// =======================================================================

function applyTheme(theme) {
  if (theme === "system") {
    theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", theme);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = theme === "light" ? "#ffffff" : "#0f1115";
}

function initTheme() {
  const saved = localStorage.getItem("theme") || "dark";
  applyTheme(saved);
  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (localStorage.getItem("theme") === "system") applyTheme("system");
  });
}

// =======================================================================
// Helpers
// =======================================================================

const screens = {
  identity: document.getElementById("identity-screen"),
  restore: document.getElementById("restore-screen"),
  backup: document.getElementById("backup-screen"),
  nameSetup: document.getElementById("name-setup-screen"),
  chats: document.getElementById("chats-screen"),
  chat: document.getElementById("chat-screen"),
};

let currentScreenName = null;

function showScreen(name) {
  Object.values(screens).forEach((el) => el.classList.add("hidden"));
  if (screens[name]) screens[name].classList.remove("hidden");
  currentScreenName = name;
}

function showModal(el) { el.classList.remove("hidden"); }
function hideModal(el) { el.classList.add("hidden"); }
function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str || "";
  return d.innerHTML;
}
function initials(name) { return (name || "?").trim().slice(0, 2).toUpperCase(); }
function fmtTime(ts) { return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
function fmtDate(ts) { return new Date(ts).toLocaleDateString([], { day: "2-digit", month: "short", year: "numeric" }); }
function fmtFileSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}
function getNodeUrl() {
  return localStorage.getItem("node_url") || DEFAULT_NODE_WS;
}

// =======================================================================
// Service worker
// =======================================================================
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

// =======================================================================
// Identidade: criar ou restaurar
// =======================================================================

document.getElementById("create-identity-btn").addEventListener("click", async () => {
  const status = document.getElementById("identity-status");
  status.textContent = "Generating keys...";
  try {
    const [keyPair, signKeyPair] = await Promise.all([
      Crypto.generateIdentityKeyPair(),
      Crypto.generateSigningKeyPair(),
    ]);

    const [publicKeyJwk, privateKeyJwk, signPublicKeyJwk, signPrivateKeyJwk] = await Promise.all([
      Crypto.exportPublicKeyJwk(keyPair.publicKey),
      Crypto.exportPrivateKeyJwk(keyPair.privateKey),
      Crypto.exportPublicKeyJwk(signKeyPair.publicKey),
      Crypto.exportPrivateKeyJwk(signKeyPair.privateKey),
    ]);

    const userId = await Crypto.deriveUserId(publicKeyJwk);

    const record = { userId, name: "", publicKeyJwk, privateKeyJwk, signPublicKeyJwk, signPrivateKeyJwk };
    await Store.put("identity", record, "me");

    me = {
      userId, name: "",
      privateKey: keyPair.privateKey, publicKeyJwk,
      signPrivateKey: signKeyPair.privateKey, signPublicKeyJwk,
    };

    const backupText = btoa(JSON.stringify({ userId, publicKeyJwk, privateKeyJwk, signPublicKeyJwk, signPrivateKeyJwk }));
    document.getElementById("backup-key-display").value = backupText;
    showScreen("backup");
  } catch (err) {
    console.error(err);
    status.textContent = "Error generating identity: " + err.message;
  }
});

document.getElementById("restore-identity-btn").addEventListener("click", () => showScreen("restore"));
document.getElementById("restore-cancel-btn").addEventListener("click", () => showScreen("identity"));

document.getElementById("restore-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.getElementById("restore-status");
  const raw = document.getElementById("restore-input").value.trim();
  try {
    status.textContent = "Restoring...";
    const parsed = JSON.parse(atob(raw));
    const privateKey = await Crypto.importPrivateKeyJwk(parsed.privateKeyJwk);
    const userId = await Crypto.deriveUserId(parsed.publicKeyJwk);
    if (userId !== parsed.userId) throw new Error("Backup key corrupted (ID mismatch)");

    // Import signing key (or handle legacy backup without one)
    let signPrivateKey = null;
    let signPublicKeyJwk = null;
    if (parsed.signPrivateKeyJwk) {
      signPrivateKey = await Crypto.importSignPrivateKeyJwk(parsed.signPrivateKeyJwk);
      signPublicKeyJwk = parsed.signPublicKeyJwk || (await Crypto.exportPublicKeyJwk(signPrivateKey));
    }

    const existing = await Store.get("identity", "me");
    const name = existing?.name || "";

    const record = {
      userId, name, publicKeyJwk: parsed.publicKeyJwk, privateKeyJwk: parsed.privateKeyJwk,
      signPublicKeyJwk: signPublicKeyJwk || parsed.signPublicKeyJwk,
      signPrivateKeyJwk: parsed.signPrivateKeyJwk,
    };
    await Store.put("identity", record, "me");

    me = { userId, name, privateKey, publicKeyJwk: parsed.publicKeyJwk, signPrivateKey, signPublicKeyJwk };

    if (name) { await connectAndEnter(); } else { showScreen("nameSetup"); }
  } catch (err) {
    console.error(err);
    status.textContent = "Invalid backup key: " + err.message;
  }
});

// Backup screen
const backupCheckbox = document.getElementById("backup-confirm-checkbox");
const backupContinueBtn = document.getElementById("backup-continue-btn");
backupCheckbox.addEventListener("change", () => { backupContinueBtn.disabled = !backupCheckbox.checked; });
document.getElementById("copy-backup-btn").addEventListener("click", () => {
  const el = document.getElementById("backup-key-display");
  el.select();
  navigator.clipboard?.writeText(el.value).catch(() => {});
});
backupContinueBtn.addEventListener("click", () => showScreen("nameSetup"));

// Name setup
document.getElementById("name-setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = document.getElementById("setup-name-input").value.trim();
  if (!name) return;
  me.name = name;
  const record = await Store.get("identity", "me");
  record.name = name;
  await Store.put("identity", record, "me");
  await connectAndEnter();
});

// =======================================================================
// WebSocket connection
// =======================================================================

async function connectAndEnter() {
  showScreen("chats");
  await connectWebSocket();
  await refreshConversations();
  await refreshNearbyUsers();
  setInterval(async () => {
    if (wsReady) await refreshNearbyUsers();
  }, 15000);
}

async function connectWebSocket() {
  if (ws) { try { ws.close(); } catch {} }
  const url = getNodeUrl();
  const statusEl = document.getElementById("connection-status");
  statusEl.textContent = `connecting to ${url}...`;

  let registerResolve = null;
  const registeredPromise = new Promise(resolve => {
    registerResolve = resolve;
    setTimeout(() => { if (registerResolve) { registerResolve(); registerResolve = null; } }, 5000);
  });

  ws = new WebSocket(url);

  ws.onopen = () => {
    wsReady = true;
    statusEl.textContent = "connected ✓";
    const displayName = me.name || me.userId.slice(0, 8);
    ws.send(JSON.stringify({
      type: "register",
      user_id: me.userId,
      public_key: me.publicKeyJwk,
      display_name: displayName,
    }));
  };

  ws.onclose = () => {
    wsReady = false;
    if (registerResolve) { registerResolve(); registerResolve = null; }
    statusEl.textContent = "disconnected — retrying in 5s...";
    setTimeout(connectWebSocket, 5000);
  };

  ws.onerror = () => { statusEl.textContent = "node connection error"; };

  ws.onmessage = async (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch { return; }

    switch (data.type) {
      case "registered":
        statusEl.textContent = `connected to node ${data.node_id || ""} ✓`;
        if (registerResolve) { registerResolve(); registerResolve = null; }
        refreshNearbyUsers();
        break;

      case "message":
        await handleIncomingEnvelope(data.envelope);
        break;

      case "friend_request":
        await handleFriendRequest(data);
        break;

      case "friend_request_sent":
        showStatusToast(`Friend request sent! Waiting...`);
        break;

      case "friend_accepted":
        await handleFriendAccepted(data);
        break;

      case "friend_declined":
        showStatusToast(`Friend request declined.`);
        break;

      case "friend_you_accepted":
        await handleFriendYouAccepted(data);
        break;

      case "receipt":
        await handleReceipt(data);
        break;

      case "typing":
        handleTypingIndicator(data);
        break;

      case "error":
        showStatusToast(data.message || "Error");
        break;

      case "pong":
        break;
    }
  };

  return registeredPromise;
}

// =======================================================================
// Friend Request System
// =======================================================================

async function handleFriendRequest(data) {
  const { request_id, from, from_alias, card } = data;
  await Store.put("friend_requests", { requestId: request_id, from, from_alias, card, ts: Date.now() });
  pendingFriendRequests.push({ requestId: request_id, from, from_alias, card });
  showFriendRequestToast(request_id, from_alias || from.slice(0, 8), card);
}

function showFriendRequestToast(requestId, alias, card) {
  const container = document.getElementById("friend-request-toast-container");
  const existing = container.querySelector(`[data-request-id="${requestId}"]`);
  if (existing) return;

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.setAttribute("data-request-id", requestId);
  toast.innerHTML = `
    <div class="avatar-circle">${escapeHtml(initials(alias))}</div>
    <div class="info">
      <strong>${escapeHtml(alias)}</strong>
      <span>wants to add you as a contact</span>
    </div>
    <div class="actions">
      <button class="btn-sm btn-accept accept-friend" data-rid="${requestId}">Accept</button>
      <button class="btn-sm btn-decline decline-friend" data-rid="${requestId}">Decline</button>
    </div>`;
  container.appendChild(toast);

  setTimeout(() => {
    const t = container.querySelector(`[data-request-id="${requestId}"]`);
    if (t) t.remove();
  }, 30000);

  toast.querySelector(".accept-friend").addEventListener("click", async () => {
    acceptFriendRequestLocally(requestId, alias, card);
    toast.remove();
  });

  toast.querySelector(".decline-friend").addEventListener("click", () => {
    if (wsReady) ws.send(JSON.stringify({ type: "friend_decline", request_id: requestId }));
    removeFriendRequest(requestId);
    toast.remove();
  });
}

async function acceptFriendRequestLocally(requestId, alias, card) {
  let parsed;
  try {
    parsed = typeof card === "object" ? card : JSON.parse(atob(card));
  } catch {
    showStatusToast("Invalid contact card");
    return;
  }

  if (!parsed.id || !parsed.publicKey) {
    showStatusToast("Invalid contact card");
    return;
  }

  if (wsReady) {
    ws.send(JSON.stringify({ type: "friend_accept", request_id: requestId }));
  }

  await saveContactAndOpen(parsed.id, alias, parsed.publicKey, parsed.signPublicKey || null);
  removeFriendRequest(requestId);
}

async function handleFriendAccepted(data) {
  const { user_id, card, alias } = data;
  let parsed;
  try {
    parsed = JSON.parse(atob(card));
  } catch {
    showStatusToast("Error processing acceptance");
    return;
  }
  await saveContactAndOpen(parsed.id || user_id, alias || user_id.slice(0, 8), parsed.publicKey || parsed.public_key, parsed.signPublicKey || null);
  showStatusToast(`${alias} accepted your request!`);
}

async function handleFriendYouAccepted(data) {
  const { user_id, card, alias } = data;
  let parsed;
  try {
    parsed = JSON.parse(atob(card));
  } catch {
    parsed = { id: user_id, publicKey: null };
  }
  await saveContactAndOpen(parsed.id || user_id, alias, parsed.publicKey, parsed.signPublicKey || null);
}

async function saveContactAndOpen(id, alias, publicKeyJwk, signPublicKeyJwk) {
  if (id === me.userId) return;
  let finalAlias = alias || id.slice(0, 8);
  await Store.put("contacts", { id, alias: finalAlias, publicKeyJwk, signPublicKeyJwk: signPublicKeyJwk || null });
  sharedKeyCache.delete(id);
  await refreshConversations();
  openChat({ id, alias: finalAlias, publicKeyJwk, signPublicKeyJwk: signPublicKeyJwk || null });
}

function removeFriendRequest(requestId) {
  pendingFriendRequests = pendingFriendRequests.filter(r => r.requestId !== requestId);
  Store.delete("friend_requests", requestId);
}

async function sendFriendRequest(toUserId, toAlias) {
  if (!wsReady) {
    showStatusToast("No node connection");
    return;
  }
  const myCard = createContactCard();
  const myAlias = me.name || me.userId.slice(0, 8);
  ws.send(JSON.stringify({
    type: "friend_request",
    to: toUserId,
    from_alias: myAlias,
    card: myCard
  }));
}

// =======================================================================
// Contact card helpers (includes signing key)
// =======================================================================

function createContactCard() {
  return btoa(JSON.stringify({
    id: me.userId,
    publicKey: me.publicKeyJwk,
    signPublicKey: me.signPublicKeyJwk,
  }));
}

function parseContactCard(raw) {
  try {
    if (typeof raw === "object" && raw.id && raw.publicKey) return raw;
    const parsed = JSON.parse(atob(raw));
    if (parsed.id && parsed.publicKey) return parsed;
    return null;
  } catch {
    return null;
  }
}

// =======================================================================
// Descoberta de rede local
// =======================================================================

async function refreshNearbyUsers() {
  if (!me) return;
  const section = document.getElementById("nearby-users-section");
  const list = document.getElementById("nearby-users-list");
  try {
    const resp = await fetch("/api/local-users");
    if (!resp.ok) { section.style.display = "none"; return; }
    const data = await resp.json();
    const contacts = await Store.getAll("contacts");
    const contactIds = new Set(contacts.map(c => c.id));
    const others = data.users.filter(u => u.user_id !== me.userId && !contactIds.has(u.user_id));
    if (others.length === 0) {
      section.style.display = "none";
      return;
    }
    section.style.display = "block";
    list.innerHTML = "";
    for (const u of others) {
      const div = document.createElement("div");
      div.className = "nearby-item";
      const alias = u.display_name || u.user_id.slice(0, 8);
      div.innerHTML = `
        <div class="avatar-circle">${escapeHtml(initials(alias))}</div>
        <div class="conversation-text">
          <div class="name">${escapeHtml(alias)}</div>
          <div class="preview">${escapeHtml(u.user_id)}</div>
        </div>
        <button class="btn-sm btn-add add-nearby-btn" data-uid="${escapeHtml(u.user_id)}" data-alias="${escapeHtml(alias)}">Add</button>`;
      list.appendChild(div);
    }
    list.querySelectorAll(".add-nearby-btn").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const uid = btn.dataset.uid;
        const alias = btn.dataset.alias;
        btn.disabled = true;
        btn.textContent = "Sending...";
        await sendFriendRequest(uid, alias);
      });
    });
  } catch {
    section.style.display = "none";
  }
}

async function refreshModalNearby() {
  const list = document.getElementById("modal-nearby-list");
  try {
    const resp = await fetch("/api/local-users");
    if (!resp.ok) { list.innerHTML = '<p class="empty-hint">Unable to load.</p>'; return; }
    const data = await resp.json();
    const contacts = await Store.getAll("contacts");
    const contactIds = new Set(contacts.map(c => c.id));
    const others = data.users.filter(u => u.user_id !== me.userId && !contactIds.has(u.user_id));
    if (others.length === 0) {
      list.innerHTML = '<p class="empty-hint">No other users on your node.</p>';
      return;
    }
    list.innerHTML = "";
    for (const u of others) {
      const alias = u.display_name || u.user_id.slice(0, 8);
      const div = document.createElement("div");
      div.className = "nearby-user";
      div.innerHTML = `
        <div class="avatar-circle">${escapeHtml(initials(alias))}</div>
        <div class="info">
          <div class="name">${escapeHtml(alias)}</div>
          <div class="id">${escapeHtml(u.user_id)}</div>
        </div>
        <button class="btn-add modal-add-btn" data-uid="${escapeHtml(u.user_id)}" data-alias="${escapeHtml(alias)}">Add</button>`;
      list.appendChild(div);
    }
    list.querySelectorAll(".modal-add-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "Sending...";
        await sendFriendRequest(btn.dataset.uid, btn.dataset.alias);
        btn.textContent = "Sent ✓";
      });
    });
  } catch {
    list.innerHTML = '<p class="empty-hint">Unable to load.</p>';
  }
}

// =======================================================================
// Network panel
// =======================================================================

async function refreshNetworkPanel(listEl) {
  try {
    const resp = await fetch("/api/network");
    if (!resp.ok) { listEl.innerHTML = '<p class="empty-hint">No network data.</p>'; return; }
    const data = await resp.json();
    if (!data.nodes || data.nodes.length === 0) {
      listEl.innerHTML = '<p class="empty-hint">No nodes connected.</p>';
      return;
    }

    const contacts = await Store.getAll("contacts");
    const contactIds = new Set(contacts.map(c => c.id));

    listEl.innerHTML = "";
    for (const node of data.nodes) {
      const div = document.createElement("div");
      div.className = "node-card" + (node.is_self ? " self" : "");

      let usersHtml = "";
      if (node.users && node.users.length > 0) {
        usersHtml = '<div class="node-users">';
        for (const u of node.users) {
          const alias = u.display_name || u.user_id.slice(0, 8);
          const isMe = u.user_id === me.userId;
          const isContact = contactIds.has(u.user_id);
          if (isMe) {
            usersHtml += `<div class="node-user-chip"><span class="uc-avatar">${escapeHtml(initials(alias))}</span>${escapeHtml(alias)}</div>`;
          } else if (isContact) {
            usersHtml += `<div class="node-user-chip" title="Already a contact"><span class="uc-avatar">${escapeHtml(initials(alias))}</span>${escapeHtml(alias)} <span class="uc-add">✓</span></div>`;
          } else {
            usersHtml += `<div class="node-user-chip add-chip" data-uid="${escapeHtml(u.user_id)}" data-alias="${escapeHtml(alias)}"><span class="uc-avatar">${escapeHtml(initials(alias))}</span>${escapeHtml(alias)} <span class="uc-add">＋</span></div>`;
          }
        }
        usersHtml += '</div>';
      } else {
        usersHtml = '<div class="node-no-users">No users on this node</div>';
      }

      div.innerHTML = `
        <div class="node-header">
          <div class="node-icon">${node.is_self ? '🏠' : '🔗'}</div>
          <div class="node-info">
            <div class="node-name">${escapeHtml(node.node_id)}</div>
            <div class="node-id">${node.is_self ? 'This device' : (node.connected ? 'Connected' : 'Disconnected')}</div>
          </div>
          <span class="node-badge ${node.is_self ? 'self-badge' : 'connected'}">${node.is_self ? 'you' : 'peer'}</span>
        </div>
        ${usersHtml}
      `;
      listEl.appendChild(div);
    }

    listEl.querySelectorAll(".add-chip").forEach(chip => {
      chip.addEventListener("click", async (e) => {
        e.stopPropagation();
        const uid = chip.dataset.uid;
        const alias = chip.dataset.alias;
        chip.style.pointerEvents = "none";
        chip.querySelector(".uc-add").textContent = "⋯";
        await sendFriendRequest(uid, alias);
      });
    });
  } catch (err) {
    console.error("Network refresh error:", err);
    listEl.innerHTML = '<p class="empty-hint">Error loading network.</p>';
  }
}

// =======================================================================
// Contatos e chave compartilhada
// =======================================================================

async function getSharedKey(contact) {
  if (sharedKeyCache.has(contact.id)) return sharedKeyCache.get(contact.id);
  if (!contact.publicKeyJwk) return null;
  const theirPublicKey = await Crypto.importPublicKeyJwk(contact.publicKeyJwk);
  const key = await Crypto.deriveSharedAesKey(me.privateKey, theirPublicKey);
  sharedKeyCache.set(contact.id, key);
  return key;
}

async function getSignPublicKey(contact) {
  if (!contact.signPublicKeyJwk) return null;
  return Crypto.importSignPublicKeyJwk(contact.signPublicKeyJwk);
}

function roomIdFor(contactId) {
  return [me.userId, contactId].sort().join("|");
}

// =======================================================================
// Enviar / receber mensagens (com assinatura digital)
// =======================================================================

async function sendMessage(contact, plaintext) {
  const aesKey = await getSharedKey(contact);
  if (!aesKey) return;

  const msgId = crypto.randomUUID();
  const ts = Date.now();

  // Build payload with reply info
  const payloadData = replyTarget
    ? { text: plaintext, replyTo: replyTarget.msgId }
    : { text: plaintext };
  const payloadJson = JSON.stringify(payloadData);

  // Sign the payload with our ECDSA private key
  let signature = null;
  if (me.signPrivateKey) {
    signature = await Crypto.sign(me.signPrivateKey, payloadJson);
  }

  // Wrap everything into the encrypted content
  const content = JSON.stringify({
    payload: payloadData,
    sig: signature,
    sigKey: me.signPublicKeyJwk,
  });

  const { iv, ciphertext } = await Crypto.encrypt(aesKey, content);
  const envelope = { to: contact.id, from: me.userId, iv, ciphertext, ts, msg_id: msgId };

  const record = {
    msgId,
    roomId: roomIdFor(contact.id),
    from: me.userId,
    to: contact.id,
    plaintext,
    replyTo: replyTarget ? replyTarget.msgId : null,
    replyPreview: replyTarget ? replyTarget.plaintext : null,
    ts,
    mine: true,
    signature,
    verified: true, // own messages are inherently verified
  };
  await Store.put("messages", record);
  renderMessageBubble(record);
  clearReply();

  if (wsReady) {
    ws.send(JSON.stringify({ type: "send", envelope }));
    // Auto-send delivery receipt to ourselves to mark as delivered
    record.delivered = true;
    await Store.put("messages", record);
    // Send delivery receipt back to sender
    if (wsReady) {
      const receiptEnvelope = { to: contact.id, from: me.userId, receipt_for: envelope.msg_id || record.msgId, ts: Date.now() };
      ws.send(JSON.stringify({ type: "receipt", envelope: receiptEnvelope, receipt_type: "delivered" }));
    }
  } else {
    showStatusToast("No connection — message saved locally");
  }

  await refreshConversations();
}

async function handleIncomingEnvelope(envelope) {
  const fromId = envelope.from;
  let contact = (await Store.getAll("contacts")).find(c => c.id === fromId);
  if (!contact || !contact.publicKeyJwk) {
    console.warn("Message from unknown contact:", fromId);
    return;
  }

  try {
    const aesKey = await getSharedKey(contact);
    if (!aesKey) return;
    const raw = await Crypto.decrypt(aesKey, envelope.iv, envelope.ciphertext);

    // Parse structured content
    let content;
    try { content = JSON.parse(raw); } catch { content = null; }

    // --- Handle file transfer ---
    if (content && content.payload && content.payload._action === "file_transfer") {
      await handleFileTransfer(content, fromId, aesKey);
      return;
    }

    // --- Handle reaction ---
    if (content && content.payload && content.payload._action === "reaction") {
      await handleIncomingReaction(content, fromId);
      return;
    }

    // --- Handle delete message ---
    if (content && content.payload && content.payload._action === "delete_message") {
      const deleteData = JSON.parse(content.payload.text || "{}");
      let deleteVerified = false;
      if (content.sig && content.sigKey) {
        try {
          const signPubKey = await Crypto.importSignPublicKeyJwk(content.sigKey);
          deleteVerified = await Crypto.verify(signPubKey, content.sig, JSON.stringify(content.payload));
        } catch {}
      }
      if (deleteVerified) {
        const target = await Store.get("messages", deleteData.msgId);
        if (target && target.from === fromId) {
          target.deleted = true;
          target.deletedAt = Date.now();
          await Store.put("messages", target);
          if (currentContact && currentContact.id === fromId) {
            rerenderChat();
          }
          await refreshConversations();
        }
      }
      return;
    }

    let payload = { text: raw };
    let signature = null;
    let verified = false;

    // Parse structured message content
    if (content && content.payload) {
      // New format with signature
      payload = content.payload;
      signature = content.sig;

      // Verify signature if we have the key
      if (signature && content.sigKey) {
        try {
          const signPubKey = await Crypto.importSignPublicKeyJwk(content.sigKey);
          verified = await Crypto.verify(signPubKey, signature, JSON.stringify(payload));
          // Save the signing key for future verification
          if (verified && !contact.signPublicKeyJwk) {
            contact.signPublicKeyJwk = content.sigKey;
            await Store.put("contacts", { ...contact, signPublicKeyJwk: content.sigKey });
          }
        } catch (sigErr) {
          console.error("Signature verification failed:", sigErr);
          verified = false;
        }
      }
    } else if (content && content.text !== undefined) {
      // Legacy format: {text, replyTo} without signature
      payload = content;
      verified = false;
    }

    let plaintext = typeof payload === "string" ? payload : (payload.text || "");
    let replyTo = payload.replyTo || null;
    let replyPreview = null;
    if (replyTo) {
      const refMsg = await Store.get("messages", replyTo);
      replyPreview = refMsg ? refMsg.plaintext : "";
    }

    const record = {
      msgId: envelope.msg_id || crypto.randomUUID(),
      roomId: roomIdFor(fromId),
      from: fromId,
      to: me.userId,
      plaintext,
      replyTo,
      replyPreview,
      ts: envelope.ts || Date.now(),
      mine: false,
      signature,
      verified,
    };
    await Store.put("messages", record);

    if (currentContact && currentContact.id === fromId) {
      renderMessageBubble(record);
    }
    await refreshConversations();
    if (currentScreenName === "chats" && (!currentContact || currentContact.id !== fromId)) {
      pulseConversationItem(fromId);
    }
  } catch (err) {
    console.error("Failed to decrypt message:", err);
  }
}

// =======================================================================
// Receipts (delivery ✓ / read ✓✓)
// =======================================================================

async function handleReceipt(data) {
  const envelope = data.envelope;
  const rtype = data.receipt_type || "delivered";
  const msgId = envelope.receipt_for;
  if (!msgId) return;

  const msg = await Store.get("messages", msgId);
  if (!msg) return;

  if (rtype === "delivered" && !msg.delivered) {
    msg.delivered = true;
    await Store.put("messages", msg);
  } else if (rtype === "read" && !msg.read) {
    msg.read = true;
    await Store.put("messages", msg);
  }

  if (currentContact && currentContact.id === envelope.from) {
    // Update receipt icon in-place
    const el = document.querySelector(`[data-msg-id="${msgId}"] .receipt`);
    if (el) {
      el.textContent = msg.read ? "✓✓" : "✓";
      if (msg.read) el.classList.add("read");
    }
  }
  await refreshConversations();
}

// Send read receipt when opening a chat
async function sendReadReceipts(contactId) {
  if (!wsReady) return;
  const roomId = roomIdFor(contactId);
  const msgs = await Store.getByIndex("messages", "roomId", roomId);
  for (const m of msgs) {
    if (!m.mine && !m.read) {
      m.read = true;
      await Store.put("messages", m);
      ws.send(JSON.stringify({
        type: "receipt",
        envelope: { to: contactId, from: me.userId, receipt_for: m.msgId, ts: Date.now() },
        receipt_type: "read",
      }));
    }
  }
}

// =======================================================================
// Typing indicator
// =======================================================================

function handleTypingIndicator(data) {
  // Different node/server implementations have sent this event using
  // different field names for "who is typing" — accept them all.
  const fromId = data.from || data.user_id || data.sender || data.sender_id || data.userId;
  console.debug("[typing] event received:", data, "resolved fromId:", fromId, "currentContact:", currentContact?.id);

  if (!currentContact || !fromId || currentContact.id !== fromId) {
    console.debug("[typing] ignored — not from current contact");
    return;
  }
  const el = document.getElementById("typing-indicator");
  const label = document.getElementById("typing-label");
  const alias = data.alias || data.display_name || data.name;
  label.textContent = alias ? `${alias} is typing...` : "typing...";
  el.classList.remove("hidden");
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => el.classList.add("hidden"), 3000);
}

function sendTypingIndicator() {
  if (!wsReady || !currentContact) return;
  const now = Date.now();
  if (now - lastTypingSent < TYPING_COOLDOWN) return;
  lastTypingSent = now;
  ws.send(JSON.stringify({
    type: "typing",
    from: me.userId,
    user_id: me.userId, // sent redundantly in case the node relays this field instead of "from"
    to: currentContact.id,
    alias: me.name || me.userId.slice(0, 8),
  }));
}

// =======================================================================
// Reactions
// =======================================================================

const reactionPicker = document.getElementById("reaction-picker");

function showReactionPicker(msgId, event) {
  reactionPickerMsgId = msgId;
  const anchor = event.currentTarget || event.target;
  const rect = anchor.getBoundingClientRect();
  reactionPicker.style.top = `${rect.top - 52}px`;
  reactionPicker.style.left = `${Math.min(rect.left, window.innerWidth - 220)}px`;
  reactionPicker.classList.remove("hidden");
}

function hideReactionPicker() {
  reactionPicker.classList.add("hidden");
  reactionPickerMsgId = null;
}

document.addEventListener("click", (e) => {
  if (!reactionPicker.classList.contains("hidden") && !reactionPicker.contains(e.target)) {
    hideReactionPicker();
  }
});

reactionPicker.querySelectorAll("button").forEach(btn => {
  btn.addEventListener("click", async () => {
    const emoji = btn.dataset.emoji;
    const msgId = reactionPickerMsgId;
    hideReactionPicker();
    if (!msgId) return;
    await toggleReaction(msgId, emoji);
  });
});

async function toggleReaction(msgId, emoji) {
  const msg = await Store.get("messages", msgId);
  if (!msg) return;
  if (!msg.reactions) msg.reactions = {};

  // Toggle: if already reacted with this emoji, remove it
  if (msg.reactions[emoji] && msg.reactions[emoji].includes(me.userId)) {
    msg.reactions[emoji] = msg.reactions[emoji].filter(id => id !== me.userId);
    if (msg.reactions[emoji].length === 0) delete msg.reactions[emoji];
  } else {
    if (!msg.reactions[emoji]) msg.reactions[emoji] = [];
    msg.reactions[emoji].push(me.userId);
  }
  await Store.put("messages", msg);

  // Send reaction to peer
  if (wsReady && currentContact && !msg.mine) {
    const contact = currentContact;
    const aesKey = await getSharedKey(contact);
    if (aesKey) {
      const reactionData = { action: "reaction", msgId, emoji, add: !!msg.reactions[emoji] };
      const content = JSON.stringify({
        payload: { text: JSON.stringify(reactionData), _action: "reaction" },
        sig: me.signPrivateKey ? await Crypto.sign(me.signPrivateKey, JSON.stringify(reactionData)) : null,
        sigKey: me.signPublicKeyJwk,
      });
      const { iv, ciphertext } = await Crypto.encrypt(aesKey, content);
      ws.send(JSON.stringify({ type: "send", envelope: { to: contact.id, from: me.userId, iv, ciphertext, ts: Date.now(), msg_id: crypto.randomUUID() } }));
    }
  }

  if (currentContact) rerenderMessageReactions(msgId);
}

function rerenderMessageReactions(msgId) {
  const el = document.querySelector(`[data-msg-id="${msgId}"]`);
  if (!el) return;
  let reactionsEl = el.querySelector(".msg-reactions");
  if (!reactionsEl) {
    // Bubble was rendered before a reactions container existed (or an
    // older cached version of the app) — create it now so reactions
    // still show up instead of silently failing.
    reactionsEl = document.createElement("div");
    reactionsEl.className = "msg-reactions";
    const reactBtn = el.querySelector(".msg-reaction-btn");
    if (reactBtn) el.insertBefore(reactionsEl, reactBtn);
    else el.appendChild(reactionsEl);
  }

  Store.get("messages", msgId).then(msg => {
    if (!msg) return;
    renderReactions(reactionsEl, msg);
  });
}

async function handleIncomingReaction(content, fromId) {
  const reactionData = JSON.parse(content.payload.text || "{}");
  const msg = await Store.get("messages", reactionData.msgId);
  if (!msg) return;
  if (!msg.reactions) msg.reactions = {};

  if (reactionData.add) {
    if (!msg.reactions[reactionData.emoji]) msg.reactions[reactionData.emoji] = [];
    if (!msg.reactions[reactionData.emoji].includes(fromId)) {
      msg.reactions[reactionData.emoji].push(fromId);
    }
  } else {
    if (msg.reactions[reactionData.emoji]) {
      msg.reactions[reactionData.emoji] = msg.reactions[reactionData.emoji].filter(id => id !== fromId);
      if (msg.reactions[reactionData.emoji].length === 0) delete msg.reactions[reactionData.emoji];
    }
  }
  await Store.put("messages", msg);
  if (currentContact && currentContact.id === fromId) {
    rerenderMessageReactions(reactionData.msgId);
  }
}

// =======================================================================
// Search
// =======================================================================

document.getElementById("toggle-search-btn").addEventListener("click", () => {
  const bar = document.getElementById("search-bar");
  const results = document.getElementById("search-results");
  const input = document.getElementById("search-input");
  bar.classList.toggle("hidden");
  if (!bar.classList.contains("hidden")) {
    input.focus();
  } else {
    input.value = "";
    results.classList.add("hidden");
    results.innerHTML = "";
  }
});

document.getElementById("close-search-btn").addEventListener("click", () => {
  document.getElementById("search-bar").classList.add("hidden");
  document.getElementById("search-results").classList.add("hidden");
  document.getElementById("search-results").innerHTML = "";
  document.getElementById("search-input").value = "";
});

document.getElementById("search-input").addEventListener("input", async (e) => {
  const query = e.target.value.trim().toLowerCase();
  const resultsEl = document.getElementById("search-results");
  if (!query || query.length < 2) {
    resultsEl.classList.add("hidden");
    resultsEl.innerHTML = "";
    return;
  }

  const allMessages = await Store.getAll("messages");
  const contacts = await Store.getAll("contacts");
  const contactMap = {};
  contacts.forEach(c => { contactMap[c.id] = c.alias || c.id.slice(0, 8); });

  const hits = allMessages.filter(m => !m.deleted && m.plaintext && m.plaintext.toLowerCase().includes(query));
  hits.sort((a, b) => b.ts - a.ts);
  const top = hits.slice(0, 20);

  if (top.length === 0) {
    resultsEl.classList.remove("hidden");
    resultsEl.innerHTML = '<p class="empty-hint">No results found</p>';
    return;
  }

  resultsEl.classList.remove("hidden");
  resultsEl.innerHTML = "";
  for (const hit of top) {
    const otherId = hit.from === me.userId ? hit.to : hit.from;
    const alias = contactMap[otherId] || otherId.slice(0, 8);
    const div = document.createElement("div");
    div.className = "search-result-item";
    const preview = hit.plaintext.length > 80 ? hit.plaintext.substring(0, 80) + "..." : hit.plaintext;
    div.innerHTML = `
      <div class="sr-name">${escapeHtml(alias)} <span class="sr-date">${fmtDate(hit.ts)}</span></div>
      <div class="sr-preview">${escapeHtml(preview)}</div>
    `;
    div.addEventListener("click", async () => {
      const contact = contacts.find(c => c.id === otherId);
      if (contact) {
        document.getElementById("search-bar").classList.add("hidden");
        resultsEl.classList.add("hidden");
        document.getElementById("search-input").value = "";
        openChat(contact);
        // Highlight the found message
        setTimeout(() => {
          const msgEl = document.querySelector(`[data-msg-id="${hit.msgId}"]`);
          if (msgEl) {
            msgEl.scrollIntoView({ behavior: "smooth", block: "center" });
            msgEl.style.outline = "2px solid var(--accent)";
            setTimeout(() => msgEl.style.outline = "", 2000);
          }
        }, 300);
      }
    });
    resultsEl.appendChild(div);
  }
});

// =======================================================================
// Delete message
// =======================================================================

async function deleteMessage(record) {
  // Mark as deleted locally
  record.deleted = true;
  record.deletedAt = Date.now();
  await Store.put("messages", record);

  // Send undelete notice to peer
  if (wsReady && currentContact) {
    const contact = currentContact;
    const aesKey = await getSharedKey(contact);
    if (aesKey) {
      const content = JSON.stringify({
        action: "delete_message",
        msgId: record.msgId,
        ts: Date.now(),
      });

      // Sign the delete request
      let signature = null;
      if (me.signPrivateKey) {
        signature = await Crypto.sign(me.signPrivateKey, content);
      }

      const wrapped = JSON.stringify({
        payload: { text: content, _action: "delete_message" },
        sig: signature,
        sigKey: me.signPublicKeyJwk,
      });

      const { iv, ciphertext } = await Crypto.encrypt(aesKey, wrapped);
      const envelope = { to: contact.id, from: me.userId, iv, ciphertext, ts: Date.now(), msg_id: crypto.randomUUID() };
      ws.send(JSON.stringify({ type: "send", envelope }));
    }
  }

  // Re-render the chat
  rerenderChat();
  await refreshConversations();
}

function rerenderChat() {
  if (!currentContact) return;
  openChat(currentContact);
}

// =======================================================================
// Delete conversation
// =======================================================================

async function deleteConversation(contactId) {
  if (!confirm("Delete this conversation and all its messages? This cannot be undone.")) return;

  const roomId = roomIdFor(contactId);

  // Delete all messages in this room
  const msgs = await Store.getByIndex("messages", "roomId", roomId);
  for (const m of msgs) {
    await Store.delete("messages", m.msgId);
  }

  // Delete the contact
  await Store.delete("contacts", contactId);
  sharedKeyCache.delete(contactId);

  // If currently viewing this chat, go back
  if (currentContact && currentContact.id === contactId) {
    currentContact = null;
    clearReply();
    showScreen("chats");
  }

  await refreshConversations();
  await refreshNearbyUsers();
}

// =======================================================================
// Encrypted File Transfer
// =======================================================================

async function handleFileTransfer(content, fromId, aesKey) {
  const fileData = content.payload;
  const transferId = fileData.transferId;

  if (fileData.type === "file_meta") {
    // Preserve pending chunks that may have arrived before metadata
    const existing = activeFileTransfers[transferId];
    const pendingChunks = existing?.pendingChunks || [];

    // Initialize transfer tracking
    activeFileTransfers[transferId] = {
      fileName: fileData.fileName,
      mimeType: fileData.mimeType,
      totalSize: fileData.totalSize,
      totalChunks: fileData.totalChunks,
      ivs: new Array(fileData.totalChunks),
      chunks: new Array(fileData.totalChunks),
      receivedChunks: 0,
    };

    // Process any chunks that arrived before metadata
    for (const pending of pendingChunks) {
      activeFileTransfers[transferId].ivs[pending.chunkIndex] = pending.iv;
      activeFileTransfers[transferId].chunks[pending.chunkIndex] = pending.data;
      activeFileTransfers[transferId].receivedChunks++;
    }

    // Check if all chunks already received
    if (activeFileTransfers[transferId].receivedChunks >= fileData.totalChunks) {
      await reassembleFile(transferId, activeFileTransfers[transferId], fromId);
    }
    return;
  }

  if (fileData.type === "file_chunk") {
    let transfer = activeFileTransfers[transferId];
    if (!transfer || transfer.pendingChunks) {
      // Metadata not received yet — accumulate chunks
      if (!activeFileTransfers[transferId]) {
        activeFileTransfers[transferId] = { pendingChunks: [] };
      } else if (!activeFileTransfers[transferId].pendingChunks) {
        activeFileTransfers[transferId].pendingChunks = [];
      }
      activeFileTransfers[transferId].pendingChunks.push({
        chunkIndex: fileData.chunkIndex, iv: fileData.iv, data: unb64(fileData.data),
      });
      return;
    }

    const chunkIndex = fileData.chunkIndex;
    transfer.ivs[chunkIndex] = fileData.iv;
    transfer.chunks[chunkIndex] = unb64(fileData.data);
    transfer.receivedChunks++;

    // Check if all chunks received
    if (transfer.receivedChunks >= transfer.totalChunks) {
      await reassembleFile(transferId, transfer, fromId);
    }
  }
}

async function reassembleFile(transferId, transfer, senderId) {
  // Decrypt each chunk and concatenate
  const decryptedChunks = [];
  const contact = (await Store.getAll("contacts")).find(c => c.id === senderId);
  if (!contact) { delete activeFileTransfers[transferId]; return; }

  const aesKey = await getSharedKey(contact);
  if (!aesKey) { delete activeFileTransfers[transferId]; return; }

  try {
    for (let i = 0; i < transfer.totalChunks; i++) {
      const iv = unb64(transfer.ivs[i]);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        transfer.chunks[i]
      );
      decryptedChunks.push(new Uint8Array(decrypted));
    }

    // Concatenate all chunks
    const totalLength = decryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const merged = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of decryptedChunks) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }

    // Save blob URL for later download (do NOT auto-download)
    const blob = new Blob([merged], { type: transfer.mimeType });
    const blobUrl = URL.createObjectURL(blob);
    const isImage = transfer.mimeType && transfer.mimeType.startsWith("image/");

    // Save file message to chat
    const record = {
      msgId: crypto.randomUUID(),
      roomId: roomIdFor(senderId),
      from: senderId,
      to: me.userId,
      plaintext: `📎 ${transfer.fileName} (${fmtFileSize(transfer.totalSize)})`,
      replyTo: null,
      replyPreview: null,
      ts: Date.now(),
      mine: false,
      fileTransfer: { fileName: transfer.fileName, mimeType: transfer.mimeType, size: transfer.totalSize, transferId, blobUrl, isImage },
      verified: true,
    };
    await Store.put("messages", record);

    // Store blobUrl on transfer for redownload
    transfer.blobUrl = blobUrl;
    transfer.fileName = transfer.fileName;

    if (currentContact && currentContact.id === senderId) {
      renderMessageBubble(record);
    }
    await refreshConversations();
    if (currentScreenName === "chats" && (!currentContact || currentContact.id !== senderId)) {
      pulseConversationItem(senderId);
    }
  } catch (err) {
    console.error("File reassembly failed:", err);
    showStatusToast("Failed to decrypt received file");
  }

  // Don't delete activeFileTransfers so blobUrl + data stay for redownload
}

// Re-download previously received file (user click)
async function downloadFile(transferId) {
  const transfer = activeFileTransfers[transferId];
  if (!transfer) {
    showStatusToast("File data no longer available (session expired)");
    return;
  }
  if (transfer.blobUrl) {
    const a = document.createElement("a");
    a.href = transfer.blobUrl;
    a.download = transfer.fileName;
    a.click();
    return;
  }
  // Reassemble from raw chunks if blobUrl not cached
  await reassembleFile(transferId, transfer, currentContact?.id);
  if (transfer.blobUrl) {
    const a = document.createElement("a");
    a.href = transfer.blobUrl;
    a.download = transfer.fileName;
    a.click();
  }
}

async function sendFile(contact, file) {
  const aesKey = await getSharedKey(contact);
  if (!aesKey) { showStatusToast("No encryption key for this contact"); return; }
  if (!wsReady) { showStatusToast("No node connection"); return; }

  showStatusToast(`Encrypting ${file.name}...`);

  const CHUNK_SIZE = 48 * 1024; // 48KB per chunk (leaves room for encryption overhead)
  const arrayBuffer = await file.arrayBuffer();
  const totalBytes = arrayBuffer.byteLength;
  const totalChunks = Math.ceil(totalBytes / CHUNK_SIZE);
  const transferId = crypto.randomUUID();

  // Prepare file metadata in IndexedDB for redownload
  activeFileTransfers[transferId] = {
    fileName: file.name,
    mimeType: file.type || "application/octet-stream",
    totalSize: totalBytes,
    totalChunks,
    ivs: new Array(totalChunks),
    chunks: new Array(totalChunks),
    receivedChunks: totalChunks, // sent by us, so "complete"
    mine: true,
  };

  // For images the sender wants a preview too — use ObjectURL from original file
  if (file.type.startsWith("image/")) {
    activeFileTransfers[transferId].blobUrl = URL.createObjectURL(file);
  }

  // Send metadata message
  const metaContent = JSON.stringify({
    payload: {
      _action: "file_transfer",
      type: "file_meta",
      transferId,
      fileName: file.name,
      mimeType: file.type || "application/octet-stream",
      totalSize: totalBytes,
      totalChunks,
    },
    sig: me.signPrivateKey ? await Crypto.sign(me.signPrivateKey, JSON.stringify({
      _action: "file_transfer", type: "file_meta", transferId, fileName: file.name,
      mimeType: file.type || "application/octet-stream", totalSize: totalBytes, totalChunks,
    })) : null,
    sigKey: me.signPublicKeyJwk,
  });

  const metaEnc = await Crypto.encrypt(aesKey, metaContent);
  ws.send(JSON.stringify({
    type: "send",
    envelope: { to: contact.id, from: me.userId, iv: metaEnc.iv, ciphertext: metaEnc.ciphertext, ts: Date.now(), msg_id: crypto.randomUUID() },
  }));

  // Send chunks
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const chunk = arrayBuffer.slice(start, Math.min(start + CHUNK_SIZE, totalBytes));

    // Encrypt chunk
    const { iv, ciphertext } = await Crypto.encryptBytes(aesKey, new Uint8Array(chunk));

    const chunkContent = JSON.stringify({
      payload: {
        _action: "file_transfer",
        type: "file_chunk",
        transferId,
        chunkIndex: i,
        iv,
        data: ciphertext,
      },
      sig: me.signPrivateKey ? await Crypto.sign(me.signPrivateKey, JSON.stringify({
        _action: "file_transfer", type: "file_chunk", transferId, chunkIndex: i, iv, data: ciphertext,
      })) : null,
      sigKey: me.signPublicKeyJwk,
    });

    const chunkEnc = await Crypto.encrypt(aesKey, chunkContent);
    ws.send(JSON.stringify({
      type: "send",
      envelope: { to: contact.id, from: me.userId, iv: chunkEnc.iv, ciphertext: chunkEnc.ciphertext, ts: Date.now(), msg_id: crypto.randomUUID() },
    }));

    // Small delay between chunks to avoid flooding
    if (i < totalChunks - 1) {
      await new Promise(r => setTimeout(r, 50));
    }
  }

  // Save file message locally
  const record = {
    msgId: crypto.randomUUID(),
    roomId: roomIdFor(contact.id),
    from: me.userId,
    to: contact.id,
    plaintext: `📎 ${file.name} (${fmtFileSize(totalBytes)})`,
    replyTo: null,
    replyPreview: null,
    ts: Date.now(),
    mine: true,
    fileTransfer: { fileName: file.name, mimeType: file.type, size: totalBytes, transferId, isImage: file.type.startsWith("image/") },
    verified: true,
  };
  await Store.put("messages", record);
  renderMessageBubble(record);
  await refreshConversations();

  showStatusToast(`${file.name} sent (${fmtFileSize(totalBytes)})`);
}

// =======================================================================
// Reply system
// =======================================================================

function setupReplyTo(msgId, plaintext) {
  replyTarget = { msgId, plaintext };
  const bar = document.getElementById("reply-bar");
  const preview = document.getElementById("reply-preview-text");
  preview.textContent = (plaintext || "").substring(0, 100);
  bar.classList.remove("hidden");
  document.getElementById("message-input").focus();
}

function clearReply() {
  replyTarget = null;
  document.getElementById("reply-bar").classList.add("hidden");
  document.getElementById("reply-preview-text").textContent = "";
}

document.getElementById("cancel-reply-btn").addEventListener("click", clearReply);

// =======================================================================
// Lista de conversas
// =======================================================================

async function refreshConversations() {
  const contacts = await Store.getAll("contacts");
  const list = document.getElementById("conversations-list");

  if (contacts.length === 0) {
    list.innerHTML = '<p class="empty-hint">No conversations yet. Tap ＋ to add a contact.</p>';
    return;
  }

  const items = [];
  for (const contact of contacts) {
    const msgs = await Store.getByIndex("messages", "roomId", roomIdFor(contact.id));
    // Filter out deleted messages for preview
    const activeMsgs = msgs.filter(m => !m.deleted);
    activeMsgs.sort((a, b) => a.ts - b.ts);
    const last = activeMsgs[activeMsgs.length - 1];
    const unreadCount = activeMsgs.filter(m => !m.mine && !m.read).length;
    items.push({ contact, last, unreadCount });
  }
  items.sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));

  list.innerHTML = "";
  for (const { contact, last, unreadCount } of items) {
    const div = document.createElement("div");
    div.className = "conversation-item" + (unreadCount > 0 ? " has-unread" : "");
    div.dataset.cid = contact.id;

    let receiptIcon = "";
    if (last && last.mine) {
      if (last.read) receiptIcon = '<span class="receipt-icon read">✓✓</span>';
      else if (last.delivered) receiptIcon = '<span class="receipt-icon">✓</span>';
    }

    let preview = last
      ? (last.mine ? "You: " : "") + (last.fileTransfer ? `📎 ${last.fileTransfer.fileName}` : last.plaintext)
      : "No messages yet";
    if (last?.deleted) preview = "[deleted]";

    const unreadBadge = unreadCount > 0
      ? `<span class="unread-badge">${unreadCount > 99 ? "99+" : unreadCount}</span>`
      : "";

    div.innerHTML = `
      <div class="avatar-circle">${escapeHtml(initials(contact.alias))}</div>
      <div class="conversation-text">
        <div class="name">${escapeHtml(contact.alias)}</div>
        <div class="preview">${receiptIcon}${escapeHtml(preview)}</div>
      </div>
      ${unreadBadge}
      <button class="btn-delete-conv" data-cid="${escapeHtml(contact.id)}" title="Delete conversation">🗑</button>`;
    div.addEventListener("click", (e) => {
      // Don't open chat if clicking delete button
      if (e.target.classList.contains("btn-delete-conv")) return;
      openChat(contact);
    });

    const deleteBtn = div.querySelector(".btn-delete-conv");
    deleteBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteConversation(contact.id);
    });

    list.appendChild(div);
  }
}

// Briefly pulses a conversation row to draw attention to a newly arrived message.
function pulseConversationItem(contactId) {
  // Wait a tick so the row exists after refreshConversations() has rebuilt the list.
  requestAnimationFrame(() => {
    const row = document.querySelector(`.conversation-item[data-cid="${CSS.escape(contactId)}"]`);
    if (!row) return;
    row.classList.remove("pulse-new-message");
    // Force reflow so the animation can restart if it's already present
    void row.offsetWidth;
    row.classList.add("pulse-new-message");
    row.addEventListener("animationend", () => row.classList.remove("pulse-new-message"), { once: true });
  });
}

// =======================================================================
// Chat individual
// =======================================================================

async function openChat(contact) {
  currentContact = contact;
  clearReply();
  clearTyping();
  document.getElementById("chat-contact-name").textContent = contact.alias;
  document.getElementById("chat-contact-id").textContent = contact.id.slice(0, 22);
  showScreen("chat");

  const messagesEl = document.getElementById("messages");
  messagesEl.innerHTML = "";
  const msgs = await Store.getByIndex("messages", "roomId", roomIdFor(contact.id));
  msgs.sort((a, b) => a.ts - b.ts);

  if (msgs.length === 0 || msgs.every(m => m.deleted)) {
    const sysDiv = document.createElement("div");
    sysDiv.className = "msg system";
    sysDiv.textContent = "No messages yet. Say hi!";
    messagesEl.appendChild(sysDiv);
  } else {
    let lastDate = "";
    for (const record of msgs) {
      if (record.deleted) continue; // skip deleted messages
      const thisDate = fmtDate(record.ts);
      if (thisDate !== lastDate) {
        lastDate = thisDate;
        const sep = document.createElement("div");
        sep.className = "date-sep";
        sep.textContent = thisDate;
        messagesEl.appendChild(sep);
      }
      renderMessageBubble(record);
    }
  }
  messagesEl.scrollTop = messagesEl.scrollHeight;
  document.getElementById("message-input").focus();
  // Send read receipts for all incoming messages in this chat
  sendReadReceipts(contact.id);
}

document.getElementById("back-to-chats-btn").addEventListener("click", async () => {
  currentContact = null;
  clearReply();
  showScreen("chats");
  await refreshConversations();
  await refreshNearbyUsers();
});

function renderMessageBubble(record) {
  if (!currentContact || record.roomId !== roomIdFor(currentContact.id) || record.deleted) return;

  const messagesEl = document.getElementById("messages");

  // Check if already rendered
  if (messagesEl.querySelector(`[data-msg-id="${record.msgId}"]`)) return;

  const div = document.createElement("div");
  div.className = "msg" + (record.mine ? " mine" : "");
  if (record.verified === false && !record.mine) {
    div.className += " unverified";
  }
  div.dataset.msgId = record.msgId;

  let html = "";
  if (record.replyPreview) {
    html += `<div class="reply-preview">↩ ${escapeHtml(record.replyPreview.substring(0, 80))}</div>`;
  }

  if (record.fileTransfer) {
    const ft = record.fileTransfer;
    const transfer = activeFileTransfers[ft.transferId];
    const blobUrl = transfer?.blobUrl || ft.blobUrl;
    const isImage = ft.isImage || (ft.mimeType && ft.mimeType.startsWith("image/"));

    if (isImage && blobUrl) {
      // Image preview
      html += `<div class="file-bubble image-preview">
        <img src="${blobUrl}" alt="${escapeHtml(ft.fileName)}" class="preview-img" onclick="event.stopPropagation()" />
        <div class="file-meta">
          <span class="file-name">${escapeHtml(ft.fileName)}</span>
          <span class="file-size">${fmtFileSize(ft.size)}</span>
        </div>
      </div>`;
    } else {
      html += `<div class="file-bubble">
        <span class="file-icon">📎</span>
        <span class="file-name">${escapeHtml(ft.fileName)}</span>
        <span class="file-size">${fmtFileSize(ft.size)}</span>
      </div>`;
    }
    if (!record.mine && transfer) {
      html += `<button class="btn-download-file" data-transfer-id="${ft.transferId}">⬇ Download</button>`;
    }
  } else {
    html += escapeHtml(record.plaintext);
  }

  // Signature indicator
  if (!record.mine && record.verified === true) {
    html += `<span class="sig-indicator" title="Verified signature">🔏</span>`;
  } else if (!record.mine && record.verified === false) {
    html += `<span class="sig-indicator unverified" title="Unverified signature">⚠️</span>`;
  }

  // Receipt + time
  let receiptHtml = "";
  if (record.mine && record.read) receiptHtml = '<span class="receipt read">✓✓</span>';
  else if (record.mine && record.delivered) receiptHtml = '<span class="receipt">✓</span>';
  else if (record.mine) receiptHtml = '<span class="receipt">◷</span>';
  html += `<span class="time">${receiptHtml} ${fmtTime(record.ts)}</span>`;

  // Reactions (container always present so it can be filled in-place later)
  html += '<div class="msg-reactions"></div>';

  // Add reaction button (long press / right click)
  html += `<span class="msg-reaction-btn" data-msg-id="${record.msgId}">＋</span>`;

  // Delete button for own messages
  if (record.mine) {
    html += `<button class="btn-delete-msg" data-msgid="${record.msgId}" title="Delete message">🗑</button>`;
  }

  div.innerHTML = html;

  // Click to reply (only on the message area, not on buttons)
  div.addEventListener("click", (e) => {
    if (e.target.classList.contains("btn-delete-msg") || e.target.classList.contains("btn-download-file")) return;
    if (e.target.classList.contains("msg-reaction-btn") || e.target.classList.contains("msg-reaction")) return;
    setupReplyTo(record.msgId, record.plaintext);
  });

  // Long-press to open the reaction picker (touch devices have no hover,
  // so the "＋" button alone isn't discoverable there)
  setupLongPressReaction(div, record.msgId);

  // Delete button handler
  const deleteMsgBtn = div.querySelector(".btn-delete-msg");
  if (deleteMsgBtn) {
    deleteMsgBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteMessage(record);
    });
  }

  // Download file button handler
  const downloadBtn = div.querySelector(".btn-download-file");
  if (downloadBtn) {
    downloadBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const tid = downloadBtn.dataset.transferId;
      if (tid) downloadFile(tid);
    });
  }

  // Reaction button handler
  const reactBtn = div.querySelector(".msg-reaction-btn");
  if (reactBtn) {
    reactBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      showReactionPicker(record.msgId, e);
    });
  }

  // Render reactions if present
  const reactionsEl = div.querySelector(".msg-reactions");
  if (reactionsEl) {
    renderReactions(reactionsEl, record);
  }

  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

document.getElementById("message-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = document.getElementById("message-input");
  const text = input.value.trim();
  if (!text || !currentContact) return;
  input.value = "";
  await sendMessage(currentContact, text);
  await refreshConversations();
  // Clear typing indicator after sending
  lastTypingSent = 0;
});

// Typing indicator on input
const messageInput = document.getElementById("message-input");
messageInput.addEventListener("input", () => sendTypingIndicator());

// =======================================================================
// File picker: attach button in chat
// =======================================================================

document.getElementById("attach-file-btn").addEventListener("click", () => {
  const fileInput = document.getElementById("file-input");
  fileInput.click();
});

document.getElementById("file-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  await handleIncomingFile(file);
  e.target.value = "";
});

// Shared entry point used by both the file picker and drag-and-drop
async function handleIncomingFile(file) {
  if (!file) return;
  if (!currentContact) return;

  // Check file size (max 50MB for browser memory)
  if (file.size > 50 * 1024 * 1024) {
    showStatusToast("File too large (max 50MB)");
    return;
  }

  await sendFile(currentContact, file);
}

// =======================================================================
// Drag & drop: attach file by dropping it onto the chat screen
// =======================================================================

(function setupFileDragAndDrop() {
  const chatScreen = document.getElementById("chat-screen");
  if (!chatScreen) return;

  let dragCounter = 0;
  let dropOverlay = document.getElementById("file-drop-overlay");
  if (!dropOverlay) {
    dropOverlay = document.createElement("div");
    dropOverlay.id = "file-drop-overlay";
    dropOverlay.className = "file-drop-overlay hidden";
    dropOverlay.innerHTML = `
      <div class="file-drop-message">
        <span class="file-drop-icon">📎</span>
        <span>Drop file to send</span>
      </div>`;
    chatScreen.appendChild(dropOverlay);
  }

  function isFileDrag(e) {
    return e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files");
  }

  function showOverlay() {
    if (!currentContact) return;
    dropOverlay.classList.remove("hidden");
  }

  function hideOverlay() {
    dropOverlay.classList.add("hidden");
  }

  chatScreen.addEventListener("dragenter", (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
    dragCounter++;
    showOverlay();
  });

  chatScreen.addEventListener("dragover", (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  });

  chatScreen.addEventListener("dragleave", (e) => {
    if (!isFileDrag(e)) return;
    dragCounter = Math.max(0, dragCounter - 1);
    if (dragCounter === 0) hideOverlay();
  });

  chatScreen.addEventListener("drop", async (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
    dragCounter = 0;
    hideOverlay();

    if (!currentContact) {
      showStatusToast("Open a conversation first");
      return;
    }

    const files = Array.from(e.dataTransfer.files || []);
    if (files.length === 0) return;

    // Send dropped files sequentially, same path as the file picker
    for (const file of files) {
      await handleIncomingFile(file);
    }
  });

  // Safety net: if the drag ends outside the window (e.g. dropped elsewhere)
  window.addEventListener("dragend", () => {
    dragCounter = 0;
    hideOverlay();
  });
})();

function clearTyping() {
  typingTimer = null;
  lastTypingSent = 0;
  document.getElementById("typing-indicator").classList.add("hidden");
}

const LONG_PRESS_MS = 420;
const LONG_PRESS_MOVE_TOLERANCE = 10; // px

function setupLongPressReaction(bubbleEl, msgId) {
  let pressTimer = null;
  let startX = 0, startY = 0;
  let longPressFired = false;

  const btn = bubbleEl.querySelector(".msg-reaction-btn");

  const clear = () => {
    clearTimeout(pressTimer);
    pressTimer = null;
    if (btn) btn.classList.remove("pressing");
  };

  bubbleEl.addEventListener("touchstart", (e) => {
    if (e.target.closest(".btn-delete-msg, .btn-download-file, .msg-reaction, .msg-reaction-btn")) return;
    longPressFired = false;
    const touch = e.touches[0];
    startX = touch.clientX;
    startY = touch.clientY;
    if (btn) btn.classList.add("pressing");
    pressTimer = setTimeout(() => {
      longPressFired = true;
      if (btn) btn.classList.remove("pressing");
      if (navigator.vibrate) navigator.vibrate(15);
      // Build a synthetic event target/rect from the bubble itself
      showReactionPicker(msgId, { currentTarget: bubbleEl });
    }, LONG_PRESS_MS);
  }, { passive: true });

  bubbleEl.addEventListener("touchmove", (e) => {
    if (!pressTimer) return;
    const touch = e.touches[0];
    if (Math.abs(touch.clientX - startX) > LONG_PRESS_MOVE_TOLERANCE ||
        Math.abs(touch.clientY - startY) > LONG_PRESS_MOVE_TOLERANCE) {
      clear();
    }
  }, { passive: true });

  bubbleEl.addEventListener("touchend", (e) => {
    if (longPressFired) {
      // Prevent the trailing synthetic "click" from also firing reply-setup
      e.preventDefault();
    }
    clear();
  });

  bubbleEl.addEventListener("touchcancel", clear);
}

function renderReactions(el, record) {
  if (!record.reactions) return;
  el.innerHTML = "";
  for (const [emoji, userIds] of Object.entries(record.reactions)) {
    if (!userIds || userIds.length === 0) continue;
    const span = document.createElement("span");
    span.className = "msg-reaction" + (userIds.includes(me.userId) ? " active" : "");
    span.textContent = emoji + " " + userIds.length;
    span.title = userIds.map(id => id === me.userId ? "You" : id.slice(0, 8)).join(", ");
    span.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleReaction(record.msgId, emoji);
    });
    el.appendChild(span);
  }
}

// =======================================================================
// Toast utility
// =======================================================================

function showStatusToast(message) {
  const container = document.getElementById("friend-request-toast-container");
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.style.borderColor = "var(--border)";
  toast.innerHTML = `<div class="info"><span>${escapeHtml(message)}</span></div>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// =======================================================================
// Configurações
// =======================================================================

// --- Top bar buttons (chats screen) ---

document.getElementById("open-network-btn").addEventListener("click", async () => {
  document.getElementById("network-modal-status").textContent = "";
  document.getElementById("peer-url-input").value = "";
  showModal(document.getElementById("network-modal"));
  await refreshNetworkPanel(document.getElementById("network-modal-list"));
});

document.getElementById("open-my-card-btn").addEventListener("click", () => {
  if (!me) return;
  const card = createContactCard();
  document.getElementById("my-card-display").value = card;
  const qrEl = document.getElementById("my-card-qr");
  qrEl.innerHTML = "";
  if (typeof QRCode !== "undefined") {
    new QRCode(qrEl, { text: card, width: 200, height: 200, colorDark: "#6c5ce7", colorLight: "#ffffff" });
  } else {
    qrEl.innerHTML = '<p class="status-text">QR Code library not loaded</p>';
  }
  showModal(document.getElementById("my-card-modal"));
});

document.getElementById("open-new-chat-btn").addEventListener("click", () => {
  document.getElementById("new-contact-card").value = "";
  document.getElementById("new-contact-alias").value = "";
  document.getElementById("new-chat-status").textContent = "";
  document.getElementById("scan-status").textContent = "";
  document.getElementById("nearby-chat-status").textContent = "";
  showModal(document.getElementById("new-chat-modal"));
  resetTabs();
  if (qrScanner) stopQrScanner();
});

// --- My card modal ---

document.getElementById("close-my-card-btn").addEventListener("click", () => hideModal(document.getElementById("my-card-modal")));
document.getElementById("copy-my-card-btn").addEventListener("click", () => {
  const el = document.getElementById("my-card-display");
  el.select();
  navigator.clipboard?.writeText(el.value).catch(() => {});
  showStatusToast("Code copied!");
});

// --- New chat modal: tabs ---

function resetTabs() {
  document.querySelectorAll(".tab-bar button").forEach(b => b.classList.remove("active"));
  const firstTab = document.querySelector('.tab-bar button[data-tab="scan"]');
  if (firstTab) firstTab.classList.add("active");
  document.getElementById("tab-scan").classList.remove("hidden");
  document.getElementById("tab-paste").classList.add("hidden");
  document.getElementById("tab-nearby").classList.add("hidden");
  document.getElementById("tab-network").classList.add("hidden");
  startQrScanner();
}

document.querySelectorAll(".tab-bar button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-bar button").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    document.getElementById("tab-scan").classList.toggle("hidden", tab !== "scan");
    document.getElementById("tab-paste").classList.toggle("hidden", tab !== "paste");
    document.getElementById("tab-nearby").classList.toggle("hidden", tab !== "nearby");
    document.getElementById("tab-network").classList.toggle("hidden", tab !== "network");
    if (tab === "scan") startQrScanner();
    if (tab !== "scan" && qrScanner) stopQrScanner();
    if (tab === "nearby") refreshModalNearby();
    if (tab === "network") refreshNetworkPanel(document.getElementById("modal-network-list"));
  });
});

// QR Scanner

function startQrScanner() {
  const readerEl = document.getElementById("qr-reader");
  if (!readerEl || typeof Html5Qrcode === "undefined") return;
  if (qrScanner) return;
  readerEl.innerHTML = "";
  qrScanner = new Html5Qrcode("qr-reader");
  const statusEl = document.getElementById("scan-status");
  qrScanner.start(
    { facingMode: "environment" },
    { fps: 5, qrbox: { width: 220, height: 220 } },
    async (decodedText) => {
      stopQrScanner();
      statusEl.textContent = "QR code read! Processing...";
      await processScannedCard(decodedText, statusEl);
    },
    () => {} // ignore scan errors
  ).catch(() => {
    statusEl.textContent = "Camera unavailable — use the Paste code tab";
    qrScanner = null;
  });
}

function stopQrScanner() {
  if (qrScanner) { qrScanner.stop().catch(() => {}); qrScanner = null; }
  const readerEl = document.getElementById("qr-reader");
  if (readerEl) readerEl.innerHTML = "";
}

async function processScannedCard(raw, statusEl) {
  const alias = prompt("Name for this contact:", "") || "";
  if (alias === null) { statusEl.textContent = ""; return; }
  await processContactCard(raw, alias, statusEl);
}

// Paste tab

document.getElementById("cancel-new-chat-btn").addEventListener("click", () => {
  if (qrScanner) stopQrScanner();
  hideModal(document.getElementById("new-chat-modal"));
});

document.getElementById("new-chat-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.getElementById("new-chat-status");
  const raw = document.getElementById("new-contact-card").value.trim();
  const alias = document.getElementById("new-contact-alias").value.trim();
  if (!alias) { status.textContent = "Enter a name"; return; }
  await processContactCard(raw, alias, status);
});

// Nearby tab

document.getElementById("cancel-nearby-btn")?.addEventListener("click", () => {
  if (qrScanner) stopQrScanner();
  hideModal(document.getElementById("new-chat-modal"));
});

// Network tab

document.getElementById("cancel-network-btn")?.addEventListener("click", () => {
  if (qrScanner) stopQrScanner();
  hideModal(document.getElementById("new-chat-modal"));
});

// --- Network modal ---

document.getElementById("close-network-modal-btn")?.addEventListener("click", () => hideModal(document.getElementById("network-modal")));

document.getElementById("connect-peer-btn")?.addEventListener("click", async () => {
  const url = document.getElementById("peer-url-input").value.trim();
  const status = document.getElementById("network-modal-status");
  if (!url) { status.textContent = "Enter the peer URL"; return; }
  status.textContent = "Connecting...";
  try {
    const resp = await fetch("/api/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await resp.json();
    if (data.status === "connecting") {
      status.textContent = "Connecting to peer... wait a few seconds.";
      setTimeout(async () => {
        await refreshNetworkPanel(document.getElementById("network-modal-list"));
        status.textContent = "Check above if the node appeared.";
      }, 3000);
    } else if (data.status === "already_connected") {
      status.textContent = "Already connected to node " + data.node_id + ".";
    } else {
      status.textContent = "Error: " + (data.error || "unknown");
    }
  } catch (err) {
    status.textContent = "Connection error: " + err.message;
  }
});

// --- Settings modal ---

document.getElementById("settings-close-btn").addEventListener("click", () => hideModal(document.getElementById("settings-modal")));

// Theme selector
document.getElementById("theme-select").addEventListener("change", (e) => {
  const theme = e.target.value;
  localStorage.setItem("theme", theme);
  applyTheme(theme);
});

// Set theme on settings open
document.getElementById("open-settings-btn").addEventListener("click", () => {
  if (!me) return;
  document.getElementById("settings-name-input").value = me.name || "";
  document.getElementById("settings-node-url").value = getNodeUrl();
  document.getElementById("settings-status").textContent = "";
  document.getElementById("theme-select").value = localStorage.getItem("theme") || "dark";
  showModal(document.getElementById("settings-modal"));
});

document.getElementById("settings-save-name-btn").addEventListener("click", async () => {
  const name = document.getElementById("settings-name-input").value.trim();
  if (!name) return;
  me.name = name;
  const record = await Store.get("identity", "me");
  record.name = name;
  await Store.put("identity", record, "me");
  if (wsReady) {
    ws.send(JSON.stringify({
      type: "register",
      user_id: me.userId,
      public_key: me.publicKeyJwk,
      display_name: name
    }));
  }
  document.getElementById("settings-status").textContent = "Name saved.";
});

document.getElementById("settings-reconnect-btn").addEventListener("click", async () => {
  const newUrl = document.getElementById("settings-node-url").value.trim();
  if (newUrl) localStorage.setItem("node_url", newUrl);
  document.getElementById("settings-status").textContent = "Reconnecting...";
  await connectWebSocket();
  await refreshConversations();
  await refreshNearbyUsers();
  document.getElementById("settings-status").textContent = "Done.";
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  if (!confirm("This will delete your identity from this device. Without the backup key, you lose access to all conversations. Continue?")) return;
  if (qrScanner) stopQrScanner();
  await Store.clearAll();
  if (ws) ws.close();
  me = null;
  location.reload();
});

// =======================================================================
// Initialization
// =======================================================================

(async function init() {
  initTheme();
  try {
    const record = await Store.get("identity", "me");
    if (!record) {
      showScreen("identity");
      return;
    }

    const privateKey = await Crypto.importPrivateKeyJwk(record.privateKeyJwk);

    // Import signing key (handle legacy backups without one)
    let signPrivateKey = null;
    let signPublicKeyJwk = record.signPublicKeyJwk || null;
    if (record.signPrivateKeyJwk) {
      try {
        signPrivateKey = await Crypto.importSignPrivateKeyJwk(record.signPrivateKeyJwk);
      } catch (e) {
        console.warn("Failed to import signing key, generating new one");
      }
    }

    // If no signing key exists, generate one now
    if (!signPrivateKey) {
      const signKeyPair = await Crypto.generateSigningKeyPair();
      signPublicKeyJwk = await Crypto.exportPublicKeyJwk(signKeyPair.publicKey);
      const signPrivateKeyJwk = await Crypto.exportPrivateKeyJwk(signKeyPair.privateKey);
      signPrivateKey = signKeyPair.privateKey;

      record.signPublicKeyJwk = signPublicKeyJwk;
      record.signPrivateKeyJwk = signPrivateKeyJwk;
      await Store.put("identity", record, "me");
    }

    me = {
      userId: record.userId,
      name: record.name,
      privateKey,
      publicKeyJwk: record.publicKeyJwk,
      signPrivateKey,
      signPublicKeyJwk,
    };

    pendingFriendRequests = await Store.getAll("friend_requests");

    if (!record.name) {
      showScreen("nameSetup");
    } else {
      await connectAndEnter();
    }
  } catch (err) {
    console.error("Error loading local identity:", err);
    showScreen("identity");
  }
})();

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
// Features: E2E encryption, QR code add, friend requests,
//           local network discovery, reply-to-message

 
 
// =======================================================================

const DEFAULT_NODE_WS = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws/client";

// =======================================================================
// Criptografia (Web Crypto API)
// =======================================================================

const Crypto = {
  async generateIdentityKeyPair() {
    return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
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
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(plaintext));
    return { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
  },

  async decrypt(aesKey, ivB64, ciphertextB64) {
    const iv = unb64(ivB64);
    const ciphertext = unb64(ciphertextB64);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
    return new TextDecoder().decode(plainBuf);
  },
};

function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(str) { return Uint8Array.from(atob(str), (c) => c.charCodeAt(0)); }
function b64url(bytes) { return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

// =======================================================================
// Armazenamento local (IndexedDB)
// =======================================================================

const Store = {
  db: null,

  async open() {
    if (this.db) return this.db;
    this.db = await new Promise((resolve, reject) => {
      const req = indexedDB.open("chat-p2p", 2);
      req.onupgradeneeded = (e) => {
        const db = req.result;
        if (!db.objectStoreNames.contains("identity")) db.createObjectStore("identity");
        if (!db.objectStoreNames.contains("contacts")) db.createObjectStore("contacts", { keyPath: "id" });
        if (!db.objectStoreNames.contains("messages")) {
          const store = db.createObjectStore("messages", { keyPath: "msgId" });
          store.createIndex("roomId", "roomId");
        }
        if (!db.objectStoreNames.contains("friend_requests")) {
          db.createObjectStore("friend_requests", { keyPath: "requestId" });
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
      const tx = db.transaction(["identity", "contacts", "messages", "friend_requests"], "readwrite");
      tx.objectStore("identity").clear();
      tx.objectStore("contacts").clear();
      tx.objectStore("messages").clear();
      tx.objectStore("friend_requests").clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },
};

// =======================================================================
// Estado da aplicação
// =======================================================================

let me = null;
let ws = null;
let wsReady = false;
let currentContact = null;
let replyTarget = null; // { msgId, plaintext }  — the message being replied to
let pendingFriendRequests = [];
let qrScanner = null;

const sharedKeyCache = new Map();

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

function showScreen(name) {
  Object.values(screens).forEach((el) => el.classList.add("hidden"));
  if (screens[name]) screens[name].classList.remove("hidden");
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
  try {
    status.textContent = "Gerando par de chaves...";
    const keyPair = await Crypto.generateIdentityKeyPair();
    const publicKeyJwk = await Crypto.exportPublicKeyJwk(keyPair.publicKey);
    const privateKeyJwk = await Crypto.exportPrivateKeyJwk(keyPair.privateKey);
    const userId = await Crypto.deriveUserId(publicKeyJwk);

    await Store.put("identity", { userId, name: "", publicKeyJwk, privateKeyJwk }, "me");
    me = { userId, name: "", privateKey: keyPair.privateKey, publicKeyJwk };

    const backupText = btoa(JSON.stringify({ userId, publicKeyJwk, privateKeyJwk }));
    document.getElementById("backup-key-display").value = backupText;
    showScreen("backup");
  } catch (err) {
    console.error(err);
    status.textContent = "Erro ao gerar identidade: " + err.message;
  }
});

document.getElementById("restore-identity-btn").addEventListener("click", () => showScreen("restore"));
document.getElementById("restore-cancel-btn").addEventListener("click", () => showScreen("identity"));

document.getElementById("restore-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = document.getElementById("restore-status");
  const raw = document.getElementById("restore-input").value.trim();
  try {
    status.textContent = "Restaurando...";
    const parsed = JSON.parse(atob(raw));
    const privateKey = await Crypto.importPrivateKeyJwk(parsed.privateKeyJwk);
    const userId = await Crypto.deriveUserId(parsed.publicKeyJwk);
    if (userId !== parsed.userId) throw new Error("chave de backup corrompida (ID não confere)");

    const existing = await Store.get("identity", "me");
    const name = existing?.name || "";

    await Store.put("identity", { userId, name, publicKeyJwk: parsed.publicKeyJwk, privateKeyJwk: parsed.privateKeyJwk }, "me");
    me = { userId, name, privateKey, publicKeyJwk: parsed.publicKeyJwk };

    if (name) { await connectAndEnter(); } else { showScreen("nameSetup"); }
  } catch (err) {
    console.error(err);
    status.textContent = "Chave de backup inválida: " + err.message;
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
  // connectWebSocket returns a promise that resolves when 'registered' is received
  await connectWebSocket();
  await refreshConversations();
  await refreshNearbyUsers();
  // periodic refresh of nearby users
  setInterval(async () => {
    if (wsReady) await refreshNearbyUsers();
  }, 15000);
}

async function connectWebSocket() {
  if (ws) { try { ws.close(); } catch {} }
  const url = getNodeUrl();
  const statusEl = document.getElementById("connection-status");
  statusEl.textContent = `conectando em ${url}...`;

  // Create a promise that resolves when the server confirms registration
  let registerResolve = null;
  const registeredPromise = new Promise(resolve => {
    registerResolve = resolve;
    setTimeout(() => { if (registerResolve) { registerResolve(); registerResolve = null; } }, 5000);
  });

  ws = new WebSocket(url);

  ws.onopen = () => {
    wsReady = true;
    statusEl.textContent = "conectado ✓";
    const displayName = me.name || me.userId.slice(0, 8);
    ws.send(JSON.stringify({
      type: "register",
      user_id: me.userId,
      public_key: me.publicKeyJwk,
      display_name: displayName
    }));
  };

  ws.onclose = () => {
    wsReady = false;
    // resolve registration promise so connectAndEnter doesn't hang forever
    if (registerResolve) { registerResolve(); registerResolve = null; }
    statusEl.textContent = "desconectado — tentando reconectar em 5s...";
    setTimeout(connectWebSocket, 5000);
  };

  ws.onerror = () => { statusEl.textContent = "erro de conexão com o nó"; };

  ws.onmessage = async (event) => {
    let data;
    try { data = JSON.parse(event.data); } catch { return; }

    switch (data.type) {
      case "registered":
        statusEl.textContent = `conectado ao nó ${data.node_id || ""} ✓`;
        // signal that registration is complete
        if (registerResolve) { registerResolve(); registerResolve = null; }
        // refresh nearby users now that we're registered
        refreshNearbyUsers();
        break;

      case "message":
        await handleIncomingEnvelope(data.envelope);
        break;

      case "friend_request":
        await handleFriendRequest(data);
        break;

      case "friend_request_sent":
        showStatusToast(`Pedido de amizade enviado! Aguardando...`);
        break;

      case "friend_accepted":
        await handleFriendAccepted(data);
        break;

      case "friend_declined":
        showStatusToast(`Pedido de amizade recusado.`);
        break;

      case "friend_you_accepted":
        await handleFriendYouAccepted(data);
        break;

      case "error":
        showStatusToast(data.message || "Erro");
        break;

      case "pong":
        break;
    }
  };

  // return promise so caller can await registration
  return registeredPromise;
}

// =======================================================================
// Friend Request System
// =======================================================================

async function handleFriendRequest(data) {
  const { request_id, from, from_alias, card } = data;
  // save to store
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
      <span>quer te adicionar como contato</span>
    </div>
    <div class="actions">
      <button class="btn-sm btn-accept accept-friend" data-rid="${requestId}">Aceitar</button>
      <button class="btn-sm btn-decline decline-friend" data-rid="${requestId}">Recusar</button>
    </div>`;
  container.appendChild(toast);

  // Auto-remove after 30s
  setTimeout(() => {
    const t = container.querySelector(`[data-request-id="${requestId}"]`);
    if (t) t.remove();
  }, 30000);

  // Accept
  toast.querySelector(".accept-friend").addEventListener("click", async () => {
    acceptFriendRequestLocally(requestId, alias, card);
    toast.remove();
  });

  // Decline
  toast.querySelector(".decline-friend").addEventListener("click", () => {
    if (wsReady) ws.send(JSON.stringify({ type: "friend_decline", request_id: requestId }));
    removeFriendRequest(requestId);
    toast.remove();
  });
}

async function acceptFriendRequestLocally(requestId, alias, card) {
  // Parse card to get publicKey
  let parsed;
  try {
    const raw = card.includes("{") ? card : JSON.parse(atob(card));
    parsed = raw.id ? raw : JSON.parse(atob(card));
  } catch {
    parsed = JSON.parse(atob(card));
  }

  if (!parsed.id || !parsed.publicKey) {
    showStatusToast("Cartão de contato inválido");
    return;
  }

  // Tell server we accept
  if (wsReady) {
    ws.send(JSON.stringify({ type: "friend_accept", request_id: requestId }));
  }

  // The server will send friend_you_accepted back, but also save locally now
  await saveContactAndOpen(parsed.id, alias, parsed.publicKey);
  removeFriendRequest(requestId);
}

async function handleFriendAccepted(data) {
  const { user_id, card, alias } = data;
  let parsed;
  try {
    parsed = JSON.parse(atob(card));
  } catch {
    showStatusToast("Erro ao processar aceitação");
    return;
  }
  await saveContactAndOpen(parsed.id || user_id, alias || user_id.slice(0, 8), parsed.publicKey || parsed.public_key);
  showStatusToast(`${alias} aceitou seu pedido!`);
}

async function handleFriendYouAccepted(data) {
  const { user_id, card, alias } = data;
  let parsed;
  try {
    parsed = JSON.parse(atob(card));
  } catch {
    parsed = { id: user_id, publicKey: null };
  }
  await saveContactAndOpen(parsed.id || user_id, alias, parsed.publicKey);
}

async function saveContactAndOpen(id, alias, publicKeyJwk) {
  if (id === me.userId) return;
  let finalAlias = alias;
  if (!finalAlias || finalAlias === id.slice(0, 8)) {
    // Try to get display name from server lookup
    try {
      const resp = await fetch(`/api/lookup/${id}`);
      if (resp.ok) {
        const data = await resp.json();
        // display_name isn't in lookup response, but alias stays
      }
    } catch {}
  }
  await Store.put("contacts", { id, alias: finalAlias || id.slice(0, 8), publicKeyJwk });
  sharedKeyCache.delete(id);
  await refreshConversations();
  openChat({ id, alias: finalAlias || id.slice(0, 8), publicKeyJwk });
}

function removeFriendRequest(requestId) {
  pendingFriendRequests = pendingFriendRequests.filter(r => r.requestId !== requestId);
  Store.delete("friend_requests", requestId);
}

async function sendFriendRequest(toUserId, toAlias) {
  if (!wsReady) {
    showStatusToast("Sem conexão com o nó");
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
// Contact card helpers
// =======================================================================

function createContactCard() {
  return btoa(JSON.stringify({ id: me.userId, publicKey: me.publicKeyJwk }));
}

function parseContactCard(raw) {
  try {
    // Try direct JSON first (friend request card)
    if (typeof raw === "object" && raw.id && raw.publicKey) return raw;
    // Try base64
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
        <button class="btn-add add-nearby-btn" data-uid="${escapeHtml(u.user_id)}" data-alias="${escapeHtml(alias)}">Adicionar</button>`;
      list.appendChild(div);
    }
    // Add event listeners
    list.querySelectorAll(".add-nearby-btn").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const uid = btn.dataset.uid;
        const alias = btn.dataset.alias;
        btn.disabled = true;
        btn.textContent = "Enviando...";
        await sendFriendRequest(uid, alias);
      });
    });
  } catch {
    section.style.display = "none";
  }
}

// Refresh nearby list in modal too
async function refreshModalNearby() {
  const list = document.getElementById("modal-nearby-list");
  try {
    const resp = await fetch("/api/local-users");
    if (!resp.ok) { list.innerHTML = '<p class="empty-hint">Não foi possível carregar.</p>'; return; }
    const data = await resp.json();
    const contacts = await Store.getAll("contacts");
    const contactIds = new Set(contacts.map(c => c.id));
    const pendingSends = new Set(); // track sent requests
    const others = data.users.filter(u => u.user_id !== me.userId && !contactIds.has(u.user_id));
    if (others.length === 0) {
      list.innerHTML = '<p class="empty-hint">Nenhum outro usuário no seu nó.</p>';
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
        <button class="btn-add modal-add-btn" data-uid="${escapeHtml(u.user_id)}" data-alias="${escapeHtml(alias)}">Adicionar</button>`;
      list.appendChild(div);
    }
    list.querySelectorAll(".modal-add-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "Enviando...";
        await sendFriendRequest(btn.dataset.uid, btn.dataset.alias);
        btn.textContent = "Enviado ✓";
      });
    });
  } catch {
    list.innerHTML = '<p class="empty-hint">Não foi possível carregar.</p>';
  }
}

// =======================================================================
// Network panel
// =======================================================================

async function refreshNetworkPanel(listEl) {
  try {
    const resp = await fetch("/api/network");
    if (!resp.ok) { listEl.innerHTML = '<p class="empty-hint">Sem dados de rede.</p>'; return; }
    const data = await resp.json();
    if (!data.nodes || data.nodes.length === 0) {
      listEl.innerHTML = '<p class="empty-hint">Nenhum nó conectado.</p>';
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
            usersHtml += `<div class="node-user-chip" title="Já é contato"><span class="uc-avatar">${escapeHtml(initials(alias))}</span>${escapeHtml(alias)} <span class="uc-add">✓</span></div>`;
          } else {
            usersHtml += `<div class="node-user-chip add-chip" data-uid="${escapeHtml(u.user_id)}" data-alias="${escapeHtml(alias)}"><span class="uc-avatar">${escapeHtml(initials(alias))}</span>${escapeHtml(alias)} <span class="uc-add">＋</span></div>`;
          }
        }
        usersHtml += '</div>';
      } else {
        usersHtml = '<div class="node-no-users">Sem usuários neste nó</div>';
      }

      div.innerHTML = `
        <div class="node-header">
          <div class="node-icon">${node.is_self ? '🏠' : '🔗'}</div>
          <div class="node-info">
            <div class="node-name">${escapeHtml(node.node_id)}</div>
            <div class="node-id">${node.is_self ? 'Este dispositivo' : (node.connected ? 'Conectado' : 'Desconectado')}</div>
          </div>
          <span class="node-badge ${node.is_self ? 'self-badge' : 'connected'}">${node.is_self ? 'você' : 'peer'}</span>
        </div>
        ${usersHtml}
      `;
      listEl.appendChild(div);
    }

    // Add event listeners for add chips
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
    listEl.innerHTML = '<p class="empty-hint">Erro ao carregar rede.</p>';
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

function roomIdFor(contactId) {
  return [me.userId, contactId].sort().join("|");
}

// =======================================================================
// Enviar / receber mensagens
// =======================================================================

async function sendMessage(contact, plaintext) {
  const aesKey = await getSharedKey(contact);
  if (!aesKey) return;
  const payload = replyTarget ? JSON.stringify({ text: plaintext, replyTo: replyTarget.msgId }) : plaintext;
  const { iv, ciphertext } = await Crypto.encrypt(aesKey, payload);
  const msgId = crypto.randomUUID();
  const envelope = { to: contact.id, from: me.userId, iv, ciphertext, ts: Date.now(), msg_id: msgId };

  const record = {
    msgId,
    roomId: roomIdFor(contact.id),
    from: me.userId,
    to: contact.id,
    plaintext,
    replyTo: replyTarget ? replyTarget.msgId : null,
    replyPreview: replyTarget ? replyTarget.plaintext : null,
    ts: envelope.ts,
    mine: true,
  };
  await Store.put("messages", record);
  renderMessageBubble(record);
  clearReply();

  if (wsReady) {
    ws.send(JSON.stringify({ type: "send", envelope }));
  } else {
    showStatusToast("Sem conexão — mensagem salva localmente");
  }

  await refreshConversations();
}

async function handleIncomingEnvelope(envelope) {
  const fromId = envelope.from;
  let contacts = await Store.getAll("contacts");
  let contact = contacts.find((c) => c.id === fromId);

  if (!contact) {
    console.warn("Mensagem de contato desconhecido:", fromId);
    return;
  }

  if (!contact.publicKeyJwk) return;

  try {
    const aesKey = await getSharedKey(contact);
    if (!aesKey) return;
    const raw = await Crypto.decrypt(aesKey, envelope.iv, envelope.ciphertext);

    let plaintext = raw;
    let replyTo = null;
    let replyPreview = null;

    try {
      const parsed = JSON.parse(raw);
      if (parsed.text && parsed.replyTo) {
        plaintext = parsed.text;
        replyTo = parsed.replyTo;
        // Try to find the referenced message for preview
        const refMsg = await Store.get("messages", replyTo);
        replyPreview = refMsg ? refMsg.plaintext : "";
      }
    } catch {
      // plain message, not JSON
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
    };
    await Store.put("messages", record);

    if (currentContact && currentContact.id === fromId) {
      renderMessageBubble(record);
    }
    await refreshConversations();
  } catch (err) {
    console.error("Falha ao decifrar mensagem:", err);
  }
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
    list.innerHTML = "";
    return;
  }

  const items = [];
  for (const contact of contacts) {
    const msgs = await Store.getByIndex("messages", "roomId", roomIdFor(contact.id));
    msgs.sort((a, b) => a.ts - b.ts);
    const last = msgs[msgs.length - 1];
    items.push({ contact, last });
  }
  items.sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));

  list.innerHTML = "";
  for (const { contact, last } of items) {
    const div = document.createElement("div");
    div.className = "conversation-item";
    let preview = last
      ? (last.mine ? "Você: " : "") + last.plaintext
      : "Nenhuma mensagem ainda";
    div.innerHTML = `
      <div class="avatar-circle">${escapeHtml(initials(contact.alias))}</div>
      <div class="conversation-text">
        <div class="name">${escapeHtml(contact.alias)}</div>
        <div class="preview">${escapeHtml(preview)}</div>
      </div>`;
    div.addEventListener("click", () => openChat(contact));
    list.appendChild(div);
  }
}

// =======================================================================
// Chat individual
// =======================================================================

async function openChat(contact) {
  currentContact = contact;
  clearReply();
  document.getElementById("chat-contact-name").textContent = contact.alias;
  document.getElementById("chat-contact-id").textContent = contact.id.slice(0, 22);
  showScreen("chat");

  const messagesEl = document.getElementById("messages");
  messagesEl.innerHTML = "";
  const msgs = await Store.getByIndex("messages", "roomId", roomIdFor(contact.id));
  msgs.sort((a, b) => a.ts - b.ts);

  // Add system message for empty chat
  if (msgs.length === 0) {
    const sysDiv = document.createElement("div");
    sysDiv.className = "msg system";
    sysDiv.textContent = "Nenhuma mensagem ainda. Diga oi!";
    messagesEl.appendChild(sysDiv);
  } else {
    let lastDate = "";
    for (const record of msgs) {
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
}

document.getElementById("back-to-chats-btn").addEventListener("click", async () => {
  currentContact = null;
  clearReply();
  showScreen("chats");
  await refreshConversations();
  await refreshNearbyUsers();
});

function renderMessageBubble(record) {
  if (!currentContact || record.roomId !== roomIdFor(currentContact.id)) return;
  const messagesEl = document.getElementById("messages");
  const div = document.createElement("div");
  div.className = "msg" + (record.mine ? " mine" : "");
  div.dataset.msgId = record.msgId;

  let html = "";
  if (record.replyPreview) {
    html += `<div class="reply-preview">↩ ${escapeHtml(record.replyPreview.substring(0, 80))}</div>`;
  }
  html += `${escapeHtml(record.plaintext)}<span class="time">${fmtTime(record.ts)}</span>`;
  div.innerHTML = html;

  // Click to reply
  div.addEventListener("click", () => {
    if (record.mine || currentContact) {
      setupReplyTo(record.msgId, record.plaintext);
    }
  });

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
});

// =======================================================================
// Meu cartão de contato + QR Code
// =======================================================================

document.getElementById("open-my-card-btn").addEventListener("click", () => {
  const card = createContactCard();
  document.getElementById("my-card-display").value = card;
  // Generate QR
  const qrEl = document.getElementById("my-card-qr");
  qrEl.innerHTML = "";
  if (typeof QRCode !== "undefined") {
    new QRCode(qrEl, {
      text: card,
      width: 200,
      height: 200,
      colorDark: "#6c5ce7",
      colorLight: "#ffffff",
    });
  } else {
    qrEl.innerHTML = '<p class="status-text">QR Code (biblioteca não carregada)</p>';
  }
  showModal(document.getElementById("my-card-modal"));
});

document.getElementById("close-my-card-btn").addEventListener("click", () => hideModal(document.getElementById("my-card-modal")));
document.getElementById("copy-my-card-btn").addEventListener("click", () => {
  const el = document.getElementById("my-card-display");
  el.select();
  navigator.clipboard?.writeText(el.value).catch(() => {});
  showStatusToast("Código copiado!");
});

// =======================================================================
// Adicionar contato — Modal com abas (Scan / Colar / Rede Local)
// =======================================================================

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

// Tab switching
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

function resetTabs() {
  document.querySelectorAll(".tab-bar button").forEach(b => b.classList.remove("active"));
  const firstTab = document.querySelector('.tab-bar button[data-tab="scan"]');
  firstTab.classList.add("active");
  document.getElementById("tab-scan").classList.remove("hidden");
  document.getElementById("tab-paste").classList.add("hidden");
  document.getElementById("tab-nearby").classList.add("hidden");
  document.getElementById("tab-network").classList.add("hidden");
  startQrScanner();
}

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
      // Got QR code
      stopQrScanner();
      statusEl.textContent = "QR code lido! Processando...";
      await processScannedCard(decodedText, statusEl);
    },
    () => {} // ignore scan errors
  ).catch(err => {
    statusEl.textContent = "Câmera indisponível — use a aba 'Colar código'";
    qrScanner = null;
  });
}

function stopQrScanner() {
  if (qrScanner) {
    qrScanner.stop().catch(() => {});
    qrScanner = null;
  }
  const readerEl = document.getElementById("qr-reader");
  if (readerEl) readerEl.innerHTML = "";
}

// Process card from any source (QR scan or paste)
async function processContactCard(raw, alias, statusEl) {
  try {
    const parsed = parseContactCard(raw);
    if (!parsed) throw new Error("Formato de cartão inválido");

    const derivedId = await Crypto.deriveUserId(parsed.publicKey);
    if (derivedId !== parsed.id) throw new Error("ID não confere com a chave pública");

    if (parsed.id === me.userId) throw new Error("Você não pode adicionar a si mesmo");

    const aliasFinal = alias || parsed.id.slice(0, 8);

    // If user is online locally, send friend request. Otherwise save directly.
    try {
      const resp = await fetch("/api/local-users");
      if (resp.ok) {
        const data = await resp.json();
        const isLocal = data.users.some(u => u.user_id === parsed.id);
        if (isLocal) {
          if (statusEl) statusEl.textContent = `Enviando pedido de amizade para ${aliasFinal}...`;
          await sendFriendRequest(parsed.id, aliasFinal);
          hideModal(document.getElementById("new-chat-modal"));
          await refreshNearbyUsers();
          return;
        }
      }
    } catch {}

    // Not local — save directly
    await Store.put("contacts", { id: parsed.id, alias: aliasFinal, publicKeyJwk: parsed.publicKey });
    sharedKeyCache.delete(parsed.id);
    hideModal(document.getElementById("new-chat-modal"));
    await refreshConversations();
    await refreshNearbyUsers();
    openChat({ id: parsed.id, alias: aliasFinal, publicKeyJwk: parsed.publicKey });
  } catch (err) {
    console.error(err);
    if (statusEl) statusEl.textContent = "Erro: " + err.message;
  }
}

async function processScannedCard(raw, statusEl) {
  const alias = prompt("Nome para este contato:", "") || "";
  if (alias === null) { statusEl.textContent = ""; return; } // cancelled
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
  if (!alias) { status.textContent = "Digite um nome"; return; }
  await processContactCard(raw, alias, status);
});

// Nearby tab
const cancelNearbyBtnEl = document.getElementById("cancel-nearby-btn");
if (cancelNearbyBtnEl) {
  cancelNearbyBtnEl.addEventListener("click", () => {
    if (qrScanner) stopQrScanner();
    hideModal(document.getElementById("new-chat-modal"));
  });
}

// Network tab (cancel button in modal)
const cancelNetworkBtnEl = document.getElementById("cancel-network-btn");
if (cancelNetworkBtnEl) {
  cancelNetworkBtnEl.addEventListener("click", () => {
    if (qrScanner) stopQrScanner();
    hideModal(document.getElementById("new-chat-modal"));
  });
}

// Network modal
const openNetworkBtn = document.getElementById("open-network-btn");
if (openNetworkBtn) {
  openNetworkBtn.addEventListener("click", async () => {
    document.getElementById("network-modal-status").textContent = "";
    document.getElementById("peer-url-input").value = "";
    showModal(document.getElementById("network-modal"));
    await refreshNetworkPanel(document.getElementById("network-modal-list"));
  });
}

const closeNetworkModalBtn = document.getElementById("close-network-modal-btn");
if (closeNetworkModalBtn) {
  closeNetworkModalBtn.addEventListener("click", () => hideModal(document.getElementById("network-modal")));
}

const connectPeerBtn = document.getElementById("connect-peer-btn");
if (connectPeerBtn) {
  connectPeerBtn.addEventListener("click", async () => {
    const url = document.getElementById("peer-url-input").value.trim();
    const status = document.getElementById("network-modal-status");
    if (!url) { status.textContent = "Digite a URL do peer"; return; }
    status.textContent = "Conectando...";
    try {
      const resp = await fetch("/api/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await resp.json();
      if (data.status === "connecting") {
        status.textContent = "Conectando ao peer... aguarde alguns segundos.";
        setTimeout(async () => {
          await refreshNetworkPanel(document.getElementById("network-modal-list"));
          status.textContent = "Verifique acima se o nó apareceu.";
        }, 3000);
      } else if (data.status === "already_connected") {
        status.textContent = `Já conectado ao nó ${data.node_id}.`;
      } else {
        status.textContent = "Erro: " + (data.error || "desconhecido");
      }
    } catch (err) {
      status.textContent = "Erro de conexão: " + err.message;
    }
  });
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

document.getElementById("open-settings-btn").addEventListener("click", () => {
  document.getElementById("settings-name-input").value = me.name || "";
  document.getElementById("settings-node-url").value = getNodeUrl();
  document.getElementById("settings-status").textContent = "";
  showModal(document.getElementById("settings-modal"));
});
document.getElementById("settings-close-btn").addEventListener("click", () => hideModal(document.getElementById("settings-modal")));

document.getElementById("settings-save-name-btn").addEventListener("click", async () => {
  const name = document.getElementById("settings-name-input").value.trim();
  if (!name) return;
  me.name = name;
  const record = await Store.get("identity", "me");
  record.name = name;
  await Store.put("identity", record, "me");
  // Re-register with new display name
  if (wsReady) {
    ws.send(JSON.stringify({
      type: "register",
      user_id: me.userId,
      public_key: me.publicKeyJwk,
      display_name: name
    }));
  }
  document.getElementById("settings-status").textContent = "Nome salvo.";
});

document.getElementById("settings-reconnect-btn").addEventListener("click", async () => {
  const newUrl = document.getElementById("settings-node-url").value.trim();
  if (newUrl) localStorage.setItem("node_url", newUrl);
  document.getElementById("settings-status").textContent = "Reconectando...";
  await connectWebSocket();
  await refreshConversations();
  await refreshNearbyUsers();
  document.getElementById("settings-status").textContent = "Feito.";
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  if (!confirm("Isso apaga sua identidade deste aparelho. Sem a chave de backup, você perde acesso a todas as conversas. Continuar?")) return;
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
  try {
    const record = await Store.get("identity", "me");
    if (!record) {
      showScreen("identity");
      return;
    }
    const privateKey = await Crypto.importPrivateKeyJwk(record.privateKeyJwk);
    me = { userId: record.userId, name: record.name, privateKey, publicKeyJwk: record.publicKeyJwk };

    // Load pending friend requests
    pendingFriendRequests = await Store.getAll("friend_requests");

    if (!record.name) {
      showScreen("nameSetup");
    } else {
      await connectAndEnter();
    }
  } catch (err) {
    console.error("Erro ao carregar identidade local:", err);
    showScreen("identity");
  }
})();

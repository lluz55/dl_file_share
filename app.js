// ────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────
const CHUNK_SIZE    = 32768; // 32 KB
const PBKDF2_ITER   = 60000;
const SALT_STORAGE  = new TextEncoder().encode('relay-storage-v1');
const SALT_CHANNEL  = new TextEncoder().encode('relay-channel-v1');
const LS_PEER_ID    = 'relay_peer_id';
const LS_HISTORY    = 'relay_history';
const LS_THEME      = 'relay_theme';
const LS_LAST_PEER  = 'relay_last_peer';
const LS_RELAY_URL  = 'relay_ws_url';
const MAX_HISTORY   = 200;
const MAX_DEBUG     = 120;

// ────────────────────────────────────────────────────────────
// Mnemonic ID — 3 palavras em português, sem acentos
// ────────────────────────────────────────────────────────────
const WORDS = ('gato lobo urso pato sapo rato bode boi vaca cobra porco arara corvo pomba carpa lula cervo zebra touro burro macaco leao onca raposa lontra tatu puma tigre lince veado tucano foca polvo grilo lagarto abelha pardal falcao gaviao cisne ganso peru mico cegonha peixe cobra baleia tartaruga rio mar lago mata ilha vale monte pedra areia terra sol lua vento chuva neve fogo bosque campo selva rocha morro praia duna lama gelo vapor pico brejo lagoa charco mangue savana colina ravina gruta caverna pantano mata mesa porta livro copo prato faca cama banco vaso caixa saco bola roda fita fio cabo rede mapa carta nota moeda chave sino frasco barco trem tocha vela anzol prego vidro tapete telha tijolo mochila bolsa grade gaiola cofre tronco galho raiz graveto tabua remo leme cesto peneira funil lupa corda escada tesoura pinca chave agulha botao prego palio arco flecha espada escudo lanterna bussola relogio forte lento leve duro mole liso vivo novo velho longo curto largo alto baixo gordo magro limpo sujo fundo raso cheio vazio quente frio doce azedo rico pobre firme calmo bravo manso claro torto reto plano curvo tenro mudo salvo livre preso pronto bom mau pao leite carne arroz milho trigo mel sal tomate cacau caju cravo cedro bambu alga musgo fungo figo uva pera amora coco manga cana aveia azeite acucar abacate morango cereja ameixa castanha porto trilha poco fonte riacho farol torre ponte arena feira aldeia vila rancho curral galpao celeiro quintal pomar jardim parque clareira encosta ladeira banco praca museu templo palco circo estadio farol ruina castelo').split(' ');

function generateMnemonicId() {
  const pick = () => WORDS[Math.floor(Math.random() * WORDS.length)];
  return `${pick()}-${pick()}-${pick()}`;
}

// ────────────────────────────────────────────────────────────
// State
// ────────────────────────────────────────────────────────────
let peer              = null;
let conn              = null;
let myId              = null;
let storageKey        = null;
let channelKey        = null;
let incoming          = {};
let sendQueue         = [];
let isSending         = false;
let reconnectAttempts = 0;
let connectTarget     = null;
let connectRetries    = 0;
const MAX_RETRIES     = 4;

let lastPeerId        = null;
let _heartbeatTimer   = null;
let _pongTimer        = null;
const PING_INTERVAL   = 15000;
const PONG_TIMEOUT    = 8000;

// Relay state
let relayWs                 = null;
let relayMode               = false;
let relayUrl                = null;
let _relayConnecting        = false; // true while connectRelay is pending
let _relayReconnectTimer    = null;
let _relayReconnectAttempts = 0;
let presenceWs              = null;  // passive listener on room=myId (rendezvous)

// ────────────────────────────────────────────────────────────
// Crypto helpers
// ────────────────────────────────────────────────────────────
async function deriveKey(secret, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  );
}

async function encryptStr(key, text) {
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(text);
  const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const out  = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return toB64(out);
}

async function decryptStr(key, b64) {
  const buf   = fromB64(b64);
  const iv    = buf.slice(0, 12);
  const ct    = buf.slice(12);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(plain);
}

async function encryptBytes(key, u8) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, u8);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return out;
}

async function decryptBytes(key, u8) {
  const iv    = u8.slice(0, 12);
  const ct    = u8.slice(12);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(plain);
}

function toB64(u8) {
  let s = '';
  const len = u8.length;
  for (let i = 0; i < len; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function fromB64(b64) {
  const s  = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

// ────────────────────────────────────────────────────────────
// Theme
// ────────────────────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : '');
  document.getElementById('btn-theme').textContent = theme === 'light' ? '◑' : '◐';
  localStorage.setItem(LS_THEME, theme);
}

function toggleTheme() {
  const cur = localStorage.getItem(LS_THEME) || 'dark';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}

// ────────────────────────────────────────────────────────────
// Debug log
// ────────────────────────────────────────────────────────────
let _debugVisible = false;

function toggleDebug() {
  _debugVisible = !_debugVisible;
  document.getElementById('debug-panel').style.display = _debugVisible ? '' : 'none';
  document.getElementById('btn-debug').classList.toggle('active', _debugVisible);
}

function clearDebug() {
  document.getElementById('debug-log').innerHTML = '<div class="debug-empty">nenhum evento ainda</div>';
}

function debugLog(tag, msg) {
  const now  = new Date();
  const time = now.toTimeString().slice(0, 8) + '.' + String(now.getMilliseconds()).padStart(3, '0');

  const fn = tag === 'error' ? console.error : console.log;
  fn(`[relay][${tag}] ${msg}`);

  const log = document.getElementById('debug-log');
  if (!log) return;
  const empty = log.querySelector('.debug-empty');
  if (empty) empty.remove();

  const entry = document.createElement('div');
  entry.className = 'debug-entry';
  entry.innerHTML = `<span class="debug-time">${time}</span>`
    + `<span class="debug-tag ${tag}">${tag}</span>`
    + `<span class="debug-msg">${esc(msg)}</span>`;
  log.appendChild(entry);

  while (log.children.length > MAX_DEBUG) log.removeChild(log.firstChild);
  log.scrollTop = log.scrollHeight;
}

// ────────────────────────────────────────────────────────────
// Heartbeat
// ────────────────────────────────────────────────────────────
function startHeartbeat() {
  stopHeartbeat();
  _heartbeatTimer = setInterval(() => {
    if (!conn || !conn.open) { stopHeartbeat(); return; }
    conn.send({ type: 'ping', ts: Date.now() });
    _pongTimer = setTimeout(() => {
      debugLog('error', 'pong timeout — connection silently dropped');
      showToast('Conexão perdida (sem resposta)');
      stopHeartbeat();
      const target = lastPeerId;
      onDisconnected();
      if (target) scheduleReconnect(target);
    }, PONG_TIMEOUT);
  }, PING_INTERVAL);
  debugLog('info', `heartbeat started (${PING_INTERVAL / 1000}s interval)`);
}

function stopHeartbeat() {
  clearInterval(_heartbeatTimer);
  clearTimeout(_pongTimer);
  _heartbeatTimer = null;
  _pongTimer      = null;
}

function scheduleReconnect(target, delay = 2000) {
  debugLog('info', `reconnecting to ${target} in ${delay / 1000}s…`);
  setStatus('connecting', 'reconectando…');
  setTimeout(() => {
    if (conn && conn.open) return;
    connectTarget  = target;
    connectRetries = 0;
    doConnect(false);
  }, delay);
}

// ────────────────────────────────────────────────────────────
// Utilities
// ────────────────────────────────────────────────────────────
function fmtBytes(n) {
  if (n < 1024)       return n + ' B';
  if (n < 1048576)    return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function uid() {
  return crypto.randomUUID().replace(/-/g,'').slice(0, 10);
}

let _toastTimer = null;
function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

// ────────────────────────────────────────────────────────────
// Status
// ────────────────────────────────────────────────────────────
function setStatus(state, text) {
  document.getElementById('status-dot').className = 'status-dot ' + state;
  document.getElementById('status-text').textContent = text;
}

// ────────────────────────────────────────────────────────────
// History — encrypted localStorage
// ────────────────────────────────────────────────────────────
async function loadHistory() {
  if (!storageKey) return [];
  const raw = localStorage.getItem(LS_HISTORY);
  if (!raw) return [];
  try   { return JSON.parse(await decryptStr(storageKey, raw)); }
  catch { return []; }
}

async function persistHistory(entries) {
  if (!storageKey) return;
  try {
    const enc = await encryptStr(storageKey, JSON.stringify(entries));
    localStorage.setItem(LS_HISTORY, enc);
  } catch {}
}

async function pushHistory(entry) {
  const entries = await loadHistory();
  entries.unshift(entry);
  if (entries.length > MAX_HISTORY) entries.length = MAX_HISTORY;
  await persistHistory(entries);
  renderHistory(entries);
}

function renderHistory(entries) {
  const list = document.getElementById('history-list');
  if (!entries || !entries.length) {
    list.innerHTML = '<div class="history-empty">nenhuma transferência ainda</div>';
    return;
  }
  list.innerHTML = entries.map(e => {
    const isFile = e.type === 'file';
    const dir    = e.direction === 'sent' ? '↑' : '↓';
    const dirCls = e.direction === 'sent' ? 'sent' : 'received';
    const name   = isFile ? esc(e.name) : `<em style="font-style:normal;">"${esc(e.text)}"</em>`;
    const meta   = isFile
      ? `${esc(fmtBytes(e.size))} · ${fmtTime(e.timestamp)}`
      : fmtTime(e.timestamp);
    return `<div class="history-item">
      <div class="h-dir ${dirCls}">${dir}</div>
      <div class="h-body">
        <div class="h-name">${name}</div>
        <div class="h-meta">${meta}</div>
      </div>
    </div>`;
  }).join('');
}

async function clearHistory() {
  if (!confirm('Apagar todo o histórico? Esta ação não pode ser desfeita.')) return;
  localStorage.removeItem(LS_HISTORY);
  renderHistory([]);
}

// ────────────────────────────────────────────────────────────
// Last-peer persistence — survives page reload, cleared on manual disconnect
// ────────────────────────────────────────────────────────────
function persistLastPeer() {
  if (!lastPeerId) return;
  localStorage.setItem(LS_LAST_PEER, lastPeerId);
}

function clearLastPeer() {
  localStorage.removeItem(LS_LAST_PEER);
}

// ────────────────────────────────────────────────────────────
// WebSocket relay
// ────────────────────────────────────────────────────────────
function saveRelayUrl(url) {
  relayUrl = url;
  localStorage.setItem(LS_RELAY_URL, url);
}

async function testRelayConnection() {
  const urlInp = document.getElementById('relay-url-input');
  const url    = urlInp ? urlInp.value.trim() : '';
  if (!url) { showToast('Informe a URL do relay WebSocket.'); return; }

  const msgEl = document.getElementById('relay-status-msg');
  if (msgEl) { msgEl.textContent = 'testando conexão…'; msgEl.style.display = ''; msgEl.className = 'tg-status-msg'; }

  debugLog('info', `relay test: conectando a ${url}`);
  try {
    await new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      const t  = setTimeout(() => { ws.close(); reject(new Error('timeout')); }, 6000);
      ws.onopen  = () => { clearTimeout(t); ws.close(); resolve(); };
      ws.onerror = () => { clearTimeout(t); reject(new Error('sem resposta')); };
    });
    if (msgEl) { msgEl.textContent = 'conectado com sucesso!'; }
    saveRelayUrl(url);
    const resetBtn = document.getElementById('btn-relay-reset');
    if (resetBtn) resetBtn.style.display = '';
    updateRelayBtnVisibility();
    startPresence(); // begin listening now that a relay URL is configured
    debugLog('info', `relay test: sucesso · URL salva: ${url}`);
  } catch (e) {
    if (msgEl) { msgEl.textContent = 'Erro: ' + e.message; msgEl.className = 'tg-status-msg error'; }
    debugLog('error', `relay test: falhou · ${e.message}`);
  }
}

function resetRelay() {
  if (!confirm('Remover configuração do relay?')) return;
  localStorage.removeItem(LS_RELAY_URL);
  relayUrl = null;
  stopPresence();
  disconnectRelay();
  const urlInp = document.getElementById('relay-url-input');
  if (urlInp) urlInp.value = '';
  const msgEl = document.getElementById('relay-status-msg');
  if (msgEl) msgEl.style.display = 'none';
  const resetBtn = document.getElementById('btn-relay-reset');
  if (resetBtn) resetBtn.style.display = 'none';
  updateRelayBtnVisibility();
}

function updateRelayBtnVisibility() {
  const btn = document.getElementById('btn-use-relay');
  if (btn) btn.style.display = (relayUrl && !relayMode) ? '' : 'none';
}

// Initiator side: join a room named after the TARGET peer's id. The target is
// passively listening on that same room via startPresence(), so the relay pairs
// us even when PeerJS signalling never delivered the connection (peer-unavailable).
function connectRelay(url, targetId) {
  return new Promise((resolve, reject) => {
    let ws;
    try { ws = new WebSocket(url); } catch (e) { reject(e); return; }

    let done = false;
    const finish = (fn) => { if (done) return; done = true; clearTimeout(connectT); clearTimeout(pairT); fn(); };

    // Phase 1: WS must open within 8s
    const connectT = setTimeout(() => finish(() => { ws.close(); reject(new Error('timeout')); }), 8000);
    let pairT = null;

    ws.onopen = () => {
      clearTimeout(connectT);
      ws.send(JSON.stringify({ type: 'join', room: targetId, peerId: myId }));
      // Phase 2: wait up to 90s for the other peer to join the room
      pairT = setTimeout(() => finish(() => { ws.close(); reject(new Error('peer não entrou no relay')); }), 90000);
      setStatus('connecting', 'aguardando peer no relay…');
    };

    ws.onmessage = async e => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.type === 'ping') {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (msg.type === 'joined') {
        if (done) return;
        done = true; clearTimeout(connectT); clearTimeout(pairT);
        await enterRelayMode(ws, msg.peerPeerId);
        resolve(msg.peerPeerId);
      } else if (msg.type === 'waiting') {
        debugLog('info', 'relay: na sala, aguardando peer…');
      } else if (msg.type === 'error') {
        finish(() => { ws.close(); reject(new Error(msg.code || 'relay error')); });
      }
    };
    ws.onerror = () => finish(() => reject(new Error('ws error')));
    ws.onclose = () => finish(() => reject(new Error('ws closed')));
  });
}

// Passive rendezvous listener: sit in a room named after our OWN id, waiting for
// any peer to initiate a relay connection toward us. Always-on (while a relay URL
// is configured and we're idle) so we're reachable even if our PeerJS signalling
// link is down. Idempotent and self-healing.
function startPresence() {
  if (!relayUrl || !myId) return;
  if (relayMode || _relayConnecting) return;
  if (presenceWs && (presenceWs.readyState === 0 || presenceWs.readyState === 1)) return;

  let ws;
  try { ws = new WebSocket(relayUrl); } catch { return; }
  presenceWs = ws;

  ws.onopen = () => {
    if (presenceWs !== ws) { ws.close(); return; }
    ws.send(JSON.stringify({ type: 'join', room: myId, peerId: myId }));
    debugLog('info', 'relay presence: escutando no relay…');
  };

  ws.onmessage = async e => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.type === 'ping') {
      if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'pong' }));
      return;
    }
    if (msg.type === 'waiting') return;
    if (msg.type === 'joined') {
      // A peer reached us through the relay — promote this socket to the active link.
      presenceWs = null; // detach so enterRelayMode doesn't close the socket we're keeping
      debugLog('info', `relay presence: peer ${msg.peerPeerId} conectou via relay`);
      await enterRelayMode(ws, msg.peerPeerId);
      return;
    }
    if (msg.type === 'error') {
      // e.g. self-join (same id in another tab) or room-full — stop quietly, no retry loop.
      debugLog('info', `relay presence: ${msg.code || 'error'}`);
      if (presenceWs === ws) presenceWs = null;
      ws.close();
    }
  };

  ws.onclose = () => {
    if (presenceWs === ws) { presenceWs = null; setTimeout(startPresence, 3000); }
  };
  ws.onerror = () => {}; // onclose will follow and handle retry
}

function stopPresence() {
  if (!presenceWs) return;
  const p = presenceWs;
  presenceWs = null;
  p.onclose = null;
  p.onerror = null;
  try { p.close(); } catch {}
}

function disconnectRelay() {
  clearTimeout(_relayReconnectTimer);
  _relayReconnectTimer = null;
  if (relayWs) {
    relayWs.onclose = null;
    relayWs.onerror = null;
    relayWs.close();
    relayWs = null;
  }
}

async function switchToRelayMode() {
  // Prevent concurrent calls: relayMode is false while connecting (relayWs not set yet)
  if (_relayConnecting || relayMode) return;
  _relayConnecting = true;

  // Close any dangling active socket from a previous attempt (presence stays up).
  disconnectRelay();

  const url = relayUrl || (document.getElementById('relay-url-input') || {}).value || '';
  if (!url) { _relayConnecting = false; showToast('Configure a URL do relay WebSocket antes.'); startPresence(); return; }

  const pid = lastPeerId || connectTarget || (conn && conn.peer)
    || document.getElementById('peer-input').value.trim();
  if (!pid) { _relayConnecting = false; showToast('Informe o ID do peer antes de usar o relay.'); startPresence(); return; }

  debugLog('info', `switching to WS relay · peer=${pid}`);

  try {
    setStatus('connecting', 'relay ws…');
    // On success, connectRelay → enterRelayMode sets all state/UI and clears _relayConnecting.
    await connectRelay(url, pid);
  } catch (e) {
    _relayConnecting = false;
    debugLog('error', `relay connect failed: ${e.message}`);
    showToast('Relay falhou: ' + e.message);
    setStatus('ready', 'pronto');
    channelKey = null;
    startPresence(); // resume listening so the peer can still reach us
  }
}

// Shared transition into relay mode, used by both roles:
//  - initiator: ws is the outbound socket from connectRelay (room = target id)
//  - listener:  ws is the presence socket that just got paired (room = my id)
// partnerId is the other peer's id, learned from the relay's `joined` message.
async function enterRelayMode(ws, partnerId) {
  if (relayMode) {
    // Already connected (glare) — drop the redundant socket.
    if (ws !== relayWs) { try { ws.close(); } catch {} }
    return;
  }

  // Tear down any in-flight P2P attempt and pending timers.
  stopHeartbeat();
  clearTimeout(_relayReconnectTimer);
  _relayReconnectTimer = null;
  if (conn) { const c = conn; conn = null; c.close(); }
  connectTarget  = null;
  connectRetries = 0;

  // Close a stray presence socket (initiator case: ws is the outbound socket).
  if (presenceWs && presenceWs !== ws) stopPresence();

  relayWs = ws;
  if (!channelKey) {
    channelKey = await deriveKey([myId, partnerId].sort().join(':'), SALT_CHANNEL);
    debugLog('info', 'channel key derived for relay');
  }
  ws.onmessage = ev => handleRelayMessage(ev.data);
  ws.onclose   = ()  => onRelayDisconnected(false);
  ws.onerror   = ()  => onRelayDisconnected(false);

  _relayConnecting = false;
  lastPeerId = partnerId;
  relayMode  = true;
  _relayReconnectAttempts = 0;
  persistLastPeer();

  const short = partnerId.length > 16 ? partnerId.slice(0, 14) + '…' : partnerId;
  document.getElementById('peer-id-badge').textContent = short;
  document.getElementById('connection-badge').classList.add('visible', 'relay-mode');
  document.getElementById('connect-form').style.display = 'none';
  document.getElementById('transfer-section').classList.add('visible');
  document.getElementById('btn-connect').disabled = false;
  setStatus('connected', 'relay ws');
  updateRelayBtnVisibility();
  showToast('Relay WebSocket ativado');
}

async function relaySend(data) {
  if (!relayWs || relayWs.readyState !== 1 || !channelKey) return;
  const payload = await encryptStr(channelKey, JSON.stringify(data));
  relayWs.send(JSON.stringify({ type: 'relay', payload }));
}

async function relaySendFile(file) {
  if (!relayWs || !channelKey) return;
  const fileId      = uid();
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;

  makeProgressItem(fileId, file.name, file.size);
  await relaySend({ type: 'file-meta', fileId, name: file.name, size: file.size, totalChunks });

  for (let i = 0; i < totalChunks; i++) {
    if (!relayWs) break;
    const start = i * CHUNK_SIZE;
    const u8    = new Uint8Array(await file.slice(start, start + CHUNK_SIZE).arrayBuffer());
    const enc   = await encryptBytes(channelKey, u8);
    await relaySend({ type: 'chunk', fileId, index: i, data: toB64(enc) });
    setProgress(fileId, (i + 1) / totalChunks);
    if (i % 8 === 0) await new Promise(r => setTimeout(r, 0));
  }

  donProgress(fileId);
  await pushHistory({ type: 'file', name: file.name, size: file.size, direction: 'sent', timestamp: Date.now() });
  debugLog('info', `relay file sent: ${file.name} (${fmtBytes(file.size)})`);
}

async function handleRelayMessage(raw) {
  let msg;
  try { msg = JSON.parse(raw); } catch { return; }

  if (msg.type === 'ping') {
    if (relayWs && relayWs.readyState === 1)
      relayWs.send(JSON.stringify({ type: 'pong' }));
    return;
  }

  if (msg.type === 'peer-left') {
    debugLog('info', 'relay: peer desconectou');
    showToast('Peer desconectou do relay');
    onRelayDisconnected(true);
    return;
  }

  if (msg.type === 'relay' && channelKey) {
    try {
      const plain = await decryptStr(channelKey, msg.payload);
      const data  = JSON.parse(plain);
      await handleData(data, true);
    } catch (e) {
      debugLog('error', `relay decrypt: ${e.message}`);
    }
  }
}

function onRelayDisconnected(peerLeft = false) {
  if (!relayMode && !relayWs && !_relayConnecting) return;
  // Close the socket before nulling — prevents dangling connections on the server
  if (relayWs) {
    relayWs.onclose = null;
    relayWs.onerror = null;
    relayWs.close();
    relayWs = null;
  }
  _relayConnecting = false;
  relayMode        = false;
  const target = lastPeerId;
  onDisconnected();
  if (target) scheduleRelayReconnect();
}

function scheduleRelayReconnect() {
  _relayReconnectAttempts++;
  const delay = Math.min(30000, _relayReconnectAttempts * 2000);
  debugLog('info', `relay reconnect in ${delay / 1000}s (tentativa ${_relayReconnectAttempts})`);
  _relayReconnectTimer = setTimeout(async () => {
    if (relayMode) return;
    try { await switchToRelayMode(); }
    catch {}
  }, delay);
}

// ────────────────────────────────────────────────────────────
// QR code
// ────────────────────────────────────────────────────────────
function buildQRUrl() {
  return `${location.origin}${location.pathname}?connect=${encodeURIComponent(myId)}`;
}

function updateQR() {
  if (!myId) return;
  const url  = buildQRUrl();
  const qrEl = document.getElementById('qr-container');
  qrEl.innerHTML = '';
  try {
    new QRCode(qrEl, {
      text: url,
      width: 120, height: 120,
      colorDark: '#111110', colorLight: '#FFFFFF',
      correctLevel: QRCode.CorrectLevel.M
    });
  } catch {}
}

// ────────────────────────────────────────────────────────────
// PeerJS
// ────────────────────────────────────────────────────────────
async function initPeer() {
  const savedId = localStorage.getItem(LS_PEER_ID) || generateMnemonicId();
  peer = new Peer(savedId, {
    debug: 1,
    config: {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302'  },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun3.l.google.com:19302' },
        { urls: 'stun:stun4.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478'  },
      ]
    }
  });

  peer.on('open', async id => {
    reconnectAttempts = 0;
    debugLog('peer', `open · id=${id}`);
    myId = id;
    localStorage.setItem(LS_PEER_ID, id);
    document.getElementById('my-id').textContent = id;

    storageKey = await deriveKey(id, SALT_STORAGE);

    const h = await loadHistory();
    renderHistory(h);

    // Load relay URL
    const savedRelayUrl = localStorage.getItem(LS_RELAY_URL);
    if (savedRelayUrl) {
      relayUrl = savedRelayUrl;
      const urlInp = document.getElementById('relay-url-input');
      if (urlInp) urlInp.value = savedRelayUrl;
      const resetBtn = document.getElementById('btn-relay-reset');
      if (resetBtn) resetBtn.style.display = '';
      updateRelayBtnVisibility();
      debugLog('info', `relay URL loaded: ${savedRelayUrl}`);
      startPresence(); // listen for inbound relay connections from the start
    }

    updateQR();
    setStatus('ready', 'pronto');

    // Parse URL params
    const p   = new URLSearchParams(location.search);
    const cid = p.get('connect');
    if (cid && cid !== id) {
      document.getElementById('peer-input').value = cid;
      connectToPeer();
    } else if (!cid) {
      // Restore last peer (persists across page reloads, cleared on manual disconnect)
      const savedPeer = localStorage.getItem(LS_LAST_PEER);
      if (savedPeer && savedPeer !== id) {
        document.getElementById('peer-input').value = savedPeer;
        debugLog('info', `restoring last peer: ${savedPeer}`);
        connectToPeer();
      }
    }
  });

  peer.on('connection', c => {
    debugLog('peer', `incoming connection from ${c.peer}`);
    if (connectTarget === c.peer) {
      debugLog('info', `glare with ${c.peer} — dropping outbound, using incoming`);
      connectTarget  = null;
      connectRetries = 0;
    }
    if (conn && conn !== c) conn.close();
    conn = c;
    setStatus('connecting', 'aguardando canal…');
    document.getElementById('btn-connect').disabled = true;
    setupConn();
  });

  peer.on('disconnected', () => {
    reconnectAttempts++;
    debugLog('peer', `disconnected from server · attempt ${reconnectAttempts} · retry in 3s`);
    setStatus('error', `sem servidor · tentativa ${reconnectAttempts}`);
    setTimeout(() => {
      if (peer && !peer.destroyed) {
        debugLog('peer', `reconnecting… (attempt ${reconnectAttempts})`);
        peer.reconnect();
      }
    }, 3000);
  });

  peer.on('error', err => {
    debugLog('error', `type=${err.type} · ${err.message || '(no message)'}`);

    if (err.type === 'unavailable-id') {
      debugLog('peer', 'id collision — regenerating');
      localStorage.removeItem(LS_PEER_ID);
      peer.destroy();
      initPeer();
      return;
    }

    if (err.type === 'negotiation-failed') {
      const target = connectTarget || (conn && conn.peer);
      connectTarget  = null;
      connectRetries = 0;
      tryRelayFallback(target);
      return;
    }

    const serverErrors = ['network', 'server-error', 'socket-error', 'socket-closed'];
    if (serverErrors.includes(err.type)) {
      const detail = err.message ? err.message.split('\n')[0].slice(0, 50) : err.type;
      const target = connectTarget;
      connectTarget  = null;
      connectRetries = 0;
      if (relayUrl && target) {
        debugLog('info', `P2P server error — fallback relay para ${target}`);
        showToast('P2P indisponível — tentando relay…');
        lastPeerId = target;
        document.getElementById('peer-input').value = target;
        switchToRelayMode();
      } else {
        setStatus('error', detail);
        showToast(`Erro de rede: ${err.type}`);
        document.getElementById('btn-connect').disabled = false;
      }
      return;
    }

    if (err.type === 'peer-unavailable' && connectTarget && connectRetries < MAX_RETRIES) {
      connectRetries++;
      const delay = connectRetries * 2000;
      debugLog('conn', `peer unavailable — retry ${connectRetries}/${MAX_RETRIES} in ${delay / 1000}s`);
      setStatus('connecting', `aguardando peer… ${connectRetries}/${MAX_RETRIES}`);
      setTimeout(doConnect, delay);
      return;
    }

    const target = connectTarget;
    connectTarget  = null;
    connectRetries = 0;
    if (relayUrl && target) {
      debugLog('info', `P2P falhou após ${MAX_RETRIES + 1} tentativas — fallback relay para ${target}`);
      showToast('Peer não encontrado via P2P — tentando relay…');
      lastPeerId = target;
      document.getElementById('peer-input').value = target;
      switchToRelayMode();
    } else {
      const msg = err.type === 'peer-unavailable'
        ? `ID não encontrado após ${MAX_RETRIES + 1} tentativas`
        : err.message || err.type || 'erro de conexão';
      setStatus('ready', 'pronto');
      showToast('Erro: ' + msg);
      document.getElementById('btn-connect').disabled = false;
    }
  });
}

function connectToPeer() {
  const tid = document.getElementById('peer-input').value.trim();
  if (!tid) return;
  if (tid === (myId || localStorage.getItem(LS_PEER_ID))) { showToast('Esse é o seu próprio ID.'); return; }

  if (conn && conn.open && conn.peer === tid) {
    debugLog('info', `already connected to ${tid}`);
    return;
  }

  // PeerJS not ready but relay is configured — go straight to relay
  if ((!peer || !myId) && relayUrl) {
    debugLog('info', `PeerJS não pronto — usando relay direto para ${tid}`);
    lastPeerId = tid;
    switchToRelayMode();
    return;
  }

  if (!peer || !myId) return;

  connectTarget  = tid;
  connectRetries = 0;
  doConnect();
}

function doConnect(disableBtn = true) {
  const tid = connectTarget;
  if (!tid || !peer || !myId) return;

  const label = connectRetries > 0 ? ` (tentativa ${connectRetries + 1}/${MAX_RETRIES + 1})` : '';
  debugLog('conn', `connecting to ${tid}${label}`);
  setStatus('connecting', connectRetries > 0 ? `reconectando… ${connectRetries + 1}` : 'conectando…');
  if (disableBtn) document.getElementById('btn-connect').disabled = true;

  if (conn) { conn.close(); conn = null; }
  conn = peer.connect(tid, { reliable: true });
  setupConn();
}

function tryRelayFallback(connPeer) {
  const target    = lastPeerId || connPeer;
  const effectiveRelayUrl = relayUrl || localStorage.getItem(LS_RELAY_URL);
  debugLog('info', `tryRelayFallback · target=${target} relayUrl=${!!effectiveRelayUrl} relayMode=${relayMode}`);
  if (effectiveRelayUrl && !relayMode && target) {
    if (!relayUrl) relayUrl = effectiveRelayUrl;
    lastPeerId = target;
    onDisconnected();
    debugLog('info', `relay fallback ativado para ${target}`);
    setTimeout(switchToRelayMode, 500);
    return true;
  }
  return false;
}

function hookICE(c, connPeer) {
  let attempts = 0;
  (function tryHook() {
    const pc = c.peerConnection;
    if (!pc) {
      if (++attempts <= 20) { setTimeout(tryHook, 200); return; }
      debugLog('error', 'peerConnection never became available after 4s');
      return;
    }
    debugLog('conn', `peerConnection available (attempt ${attempts})`);
    pc.addEventListener('iceconnectionstatechange', () => {
      debugLog('conn', `ICE → ${pc.iceConnectionState}`);
      if (pc.iceConnectionState === 'failed') {
        debugLog('error', 'ICE failed — NAT traversal blocked; TURN server needed');
        showToast('Falha ICE: sem rota direta entre os dispositivos');
        tryRelayFallback(connPeer);
      }
    });
    pc.addEventListener('icegatheringstatechange', () => {
      debugLog('conn', `ICE gathering → ${pc.iceGatheringState}`);
    });
    pc.addEventListener('connectionstatechange', () => {
      debugLog('conn', `RTC → ${pc.connectionState}`);
      if (pc.connectionState === 'failed') {
        debugLog('error', 'RTC connection failed — NAT traversal blocked');
        showToast('Falha de conexão: sem rota direta entre os dispositivos');
        tryRelayFallback(connPeer);
      }
    });
  })();
}

function setupConn() {
  const _connPeer = conn.peer; // capture before any async reassignment
  hookICE(conn, _connPeer);

  const _connTimeout = setTimeout(() => {
    debugLog('error', 'connection timeout (20s) — ICE negotiation stalled');
    showToast('Tempo esgotado: verifique a rede ou bloqueio de firewall');
    tryRelayFallback(_connPeer);
  }, 20000);

  conn.on('open', async () => {
    clearTimeout(_connTimeout);
    connectTarget  = null;
    connectRetries = 0;
    const pid  = _connPeer;
    lastPeerId = pid;
    persistLastPeer();
    debugLog('conn', `open · peer=${pid}`);
    channelKey = await deriveKey([myId, pid].sort().join(':'), SALT_CHANNEL);
    debugLog('info', 'channel key derived');
    startHeartbeat();

    setStatus('connected', 'conectado');
    const short = pid.length > 16 ? pid.slice(0, 14) + '…' : pid;
    document.getElementById('peer-id-badge').textContent = short;
    document.getElementById('connection-badge').classList.add('visible');
    document.getElementById('connect-form').style.display = 'none';
    document.getElementById('transfer-section').classList.add('visible');
    document.getElementById('btn-connect').disabled = false;
    updateRelayBtnVisibility();
  });

  conn.on('data', data => handleData(data, false));

  conn.on('close', () => {
    clearTimeout(_connTimeout);
    stopHeartbeat();
    debugLog('conn', 'closed');
    const wasConnected = !!lastPeerId;
    const target = lastPeerId || _connPeer;
    // only try relay if connection never opened (pre-handshake failure)
    if (!wasConnected && tryRelayFallback(_connPeer)) return;
    onDisconnected();
    if (target) scheduleReconnect(target);
  });

  conn.on('error', e => {
    clearTimeout(_connTimeout);
    stopHeartbeat();
    debugLog('error', `conn · ${e.message || e.type || String(e)}`);
    if (!tryRelayFallback(_connPeer)) {
      const target = lastPeerId || _connPeer;
      onDisconnected();
      if (target) scheduleReconnect(target);
    }
  });
}

function onDisconnected() {
  debugLog('info', 'state reset · waiting for connection');
  stopHeartbeat();
  connectTarget  = null;
  connectRetries = 0;
  relayMode      = false;
  setStatus('ready', 'pronto');
  document.getElementById('connection-badge').classList.remove('visible', 'relay-mode');
  document.getElementById('connect-form').style.display = '';
  document.getElementById('transfer-section').classList.remove('visible');
  document.getElementById('transfers-list').innerHTML = '';
  channelKey = null;
  conn       = null;
  incoming   = {};
  sendQueue  = [];
  isSending  = false;
  document.getElementById('btn-connect').disabled = false;
  updateRelayBtnVisibility();
  startPresence(); // back to idle — resume listening for inbound relay connections
}

function disconnect() {
  lastPeerId = null; // manual disconnect — don't auto-reconnect
  clearLastPeer();
  stopHeartbeat();
  disconnectRelay();
  relayMode = false;
  if (conn) { conn.close(); }
  onDisconnected();
}

// ────────────────────────────────────────────────────────────
// Incoming data
// ────────────────────────────────────────────────────────────
async function handleData(data, fromRelay = false) {
  try {
    if (data.type === 'ping') {
      if (!relayMode) conn.send({ type: 'pong', ts: data.ts });
      return;
    }

    if (data.type === 'pong') {
      const rtt = Date.now() - data.ts;
      debugLog('info', `pong · rtt=${rtt}ms`);
      clearTimeout(_pongTimer);
      _pongTimer = null;
      return;
    }

    if (data.type === 'file-meta') {
      incoming[data.fileId] = {
        meta: data,
        chunks: new Array(data.totalChunks),
        received: 0
      };
      makeProgressItem(data.fileId, data.name, data.size);
      return;
    }

    if (data.type === 'chunk') {
      const f = incoming[data.fileId];
      if (!f) return;
      let bytes = fromB64(data.data);
      if (fromRelay && channelKey) {
        try { bytes = await decryptBytes(channelKey, bytes); } catch {}
      }
      f.chunks[data.index] = bytes;
      f.received++;
      setProgress(data.fileId, f.received / f.meta.totalChunks);
      if (f.received === f.meta.totalChunks) assembleAndDownload(data.fileId);
      return;
    }

    if (data.type === 'message') {
      let text = data.text;
      // relay payloads are already decrypted; P2P payloads need decryption
      if (!fromRelay && channelKey) {
        try { text = await decryptStr(channelKey, data.text); } catch {}
      }
      await pushHistory({ type: 'message', text, direction: 'received', timestamp: data.ts || Date.now() });
      return;
    }
  } catch (e) {
    console.error('handleData error', e);
  }
}

function assembleAndDownload(fileId) {
  const f = incoming[fileId];
  if (!f) return;

  let total = 0;
  for (const c of f.chunks) total += c.length;

  const out = new Uint8Array(total);
  let off = 0;
  for (const c of f.chunks) { out.set(c, off); off += c.length; }

  const blob = new Blob([out]);
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = f.meta.name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);

  donProgress(fileId);
  delete incoming[fileId];
  pushHistory({ type: 'file', name: f.meta.name, size: f.meta.size, direction: 'received', timestamp: Date.now() });
}

// ────────────────────────────────────────────────────────────
// Sending
// ────────────────────────────────────────────────────────────
async function handleFileSelect(files) {
  if ((!conn && !relayMode) || !files.length) return;
  const arr     = Array.from(files);
  const zipMode = document.getElementById('zip-mode').checked && arr.length > 1;

  if (zipMode) {
    const zip     = new JSZip();
    const ts      = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    const zipName = `relay-${ts}.zip`;

    const packId = uid();
    makeProgressItem(packId, `compactando ${arr.length} arquivos…`, 0);
    for (let i = 0; i < arr.length; i++) {
      zip.file(arr[i].name, arr[i]);
      setProgress(packId, (i + 1) / arr.length * 0.3);
    }

    const blob = await zip.generateAsync(
      { type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } },
      meta => setProgress(packId, 0.3 + meta.percent / 100 * 0.7)
    );
    donProgress(packId);

    sendQueue.push(new File([blob], zipName, { type: 'application/zip' }));
  } else {
    for (const f of arr) sendQueue.push(f);
  }

  processSendQueue();
}

async function processSendQueue() {
  if (isSending) return;
  isSending = true;
  while (sendQueue.length && (conn || relayMode)) {
    const file = sendQueue.shift();
    if (relayMode) {
      await relaySendFile(file);
    } else {
      await sendFile(file);
    }
  }
  isSending = false;
}

async function sendFile(file) {
  const fileId      = uid();
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE) || 1;

  makeProgressItem(fileId, file.name, file.size);
  conn.send({ type: 'file-meta', fileId, name: file.name, size: file.size, totalChunks });

  for (let i = 0; i < totalChunks; i++) {
    if (!conn) break;
    const start = i * CHUNK_SIZE;
    const end   = Math.min(start + CHUNK_SIZE, file.size);
    const buf   = await file.slice(start, end).arrayBuffer();
    conn.send({ type: 'chunk', fileId, index: i, data: toB64(new Uint8Array(buf)) });
    setProgress(fileId, (i + 1) / totalChunks);
    if (i % 8 === 0) await new Promise(r => setTimeout(r, 0));
  }

  donProgress(fileId);
  await pushHistory({ type: 'file', name: file.name, size: file.size, direction: 'sent', timestamp: Date.now() });
}

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text  = input.value.trim();
  if (!text || (!conn && !relayMode)) return;

  if (relayMode) {
    await relaySend({ type: 'message', text, ts: Date.now() });
    input.value = '';
    await pushHistory({ type: 'message', text, direction: 'sent', timestamp: Date.now() });
    return;
  }

  let encText = text;
  if (channelKey) {
    try { encText = await encryptStr(channelKey, text); } catch {}
  }
  conn.send({ type: 'message', text: encText, ts: Date.now() });
  input.value = '';
  await pushHistory({ type: 'message', text, direction: 'sent', timestamp: Date.now() });
}

// ────────────────────────────────────────────────────────────
// Progress UI
// ────────────────────────────────────────────────────────────
function makeProgressItem(fileId, name, size) {
  const list = document.getElementById('transfers-list');
  const el   = document.createElement('div');
  el.className = 'transfer-item';
  el.id = 'tx-' + fileId;
  el.innerHTML = `
    <div class="transfer-row">
      <div class="transfer-name">${esc(name)}</div>
      <div class="transfer-size">${esc(fmtBytes(size))}</div>
    </div>
    <div class="progress-track">
      <div class="progress-fill" id="pf-${fileId}"></div>
    </div>`;
  list.prepend(el);
}

function setProgress(fileId, ratio) {
  const el = document.getElementById('pf-' + fileId);
  if (el) el.style.width = Math.min(Math.round(ratio * 100), 100) + '%';
}

function donProgress(fileId) {
  const el = document.getElementById('pf-' + fileId);
  if (el) { el.style.width = '100%'; el.classList.add('done'); }
  setTimeout(() => {
    const item = document.getElementById('tx-' + fileId);
    if (item) item.style.opacity = '0';
    setTimeout(() => { if (item) item.remove(); }, 300);
  }, 1800);
}

// ────────────────────────────────────────────────────────────
// Copy peer ID
// ────────────────────────────────────────────────────────────
function copyId() {
  if (!myId) return;
  navigator.clipboard.writeText(myId).then(() => {
    const btn  = document.getElementById('btn-copy');
    const prev = btn.textContent;
    btn.textContent = 'copiado!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = prev; btn.classList.remove('copied'); }, 2200);
  }).catch(() => showToast('Não foi possível copiar.'));
}

// ────────────────────────────────────────────────────────────
// Drag & Drop
// ────────────────────────────────────────────────────────────
const dropZone  = document.getElementById('drop-zone');
let dragCounter = 0;

dropZone.addEventListener('dragenter', e => { e.preventDefault(); dragCounter++; dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', ()  => { dragCounter--; if (!dragCounter) dropZone.classList.remove('drag-over'); });
dropZone.addEventListener('dragover',  e  => e.preventDefault());
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dragCounter = 0;
  dropZone.classList.remove('drag-over');
  handleFileSelect(e.dataTransfer.files);
});

// ────────────────────────────────────────────────────────────
// Boot
// ────────────────────────────────────────────────────────────
applyTheme(localStorage.getItem(LS_THEME) || 'dark');
if (typeof RELAY_COMMIT !== 'undefined') {
  const el = document.getElementById('commit-hash');
  if (el) el.textContent = RELAY_COMMIT;
}
debugLog('info', 'relay starting…');

if (typeof Peer === 'undefined') {
  debugLog('error', 'PeerJS library not loaded — check network/CSP');
  setStatus('error', 'biblioteca não carregou');
  showToast('Erro: PeerJS não carregou. Verifique a conexão.');
} else {
  try {
    initPeer();
  } catch (e) {
    debugLog('error', `initPeer threw: ${e.message || e}`);
    setStatus('error', 'falha ao iniciar');
  }
}

window.addEventListener('unhandledrejection', e => {
  debugLog('error', `unhandled promise rejection: ${e.reason}`);
});

window.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeTgGuide();
});

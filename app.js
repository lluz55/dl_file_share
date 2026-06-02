// ────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────
const CHUNK_SIZE    = 32768; // 32 KB
const PBKDF2_ITER   = 60000;
const SALT_STORAGE  = new TextEncoder().encode('relay-storage-v1');
const SALT_CHANNEL  = new TextEncoder().encode('relay-channel-v1');
const LS_PEER_ID      = 'relay_peer_id';
const LS_HISTORY      = 'relay_history';
const LS_THEME        = 'relay_theme';
const LS_LAST_PEER    = 'relay_last_peer';
const LS_PEER_TG_CHAT = 'relay_peer_tg_chat';
const LS_TG_TOKEN    = 'relay_tg_token';
const LS_TG_CHAT_ID  = 'relay_tg_chat_id';
const LS_TG_GROUP_ID = 'relay_tg_group_id';
const SALT_TG        = new TextEncoder().encode('relay-tg-v1');
const TG_MAX_FILE   = 50 * 1024 * 1024; // 50 MB
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

// Telegram state
let tgToken           = null;
let myTgChatId        = null;
let peerTgChatId      = null;
let tgGroupId         = null;  // shared group/channel for relay (enables getUpdates to work)
let tgMode            = false;
let tgPollOffset      = 0;
let tgAbortCtrl       = null;
let _discoverAbortCtrl = null;

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
    doConnect();
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
  if (peerTgChatId) {
    localStorage.setItem(LS_PEER_TG_CHAT, String(peerTgChatId));
  } else {
    localStorage.removeItem(LS_PEER_TG_CHAT);
  }
}

function clearLastPeer() {
  localStorage.removeItem(LS_LAST_PEER);
  localStorage.removeItem(LS_PEER_TG_CHAT);
}

// ────────────────────────────────────────────────────────────
// Telegram — token storage (uses storageKey, available after peer opens)
// ────────────────────────────────────────────────────────────
async function saveTgToken(plain) {
  if (!storageKey) return;
  localStorage.setItem(LS_TG_TOKEN, await encryptStr(storageKey, plain));
}

async function loadTgToken() {
  if (!storageKey) return null;
  const raw = localStorage.getItem(LS_TG_TOKEN);
  if (!raw) return null;
  try   { return await decryptStr(storageKey, raw); }
  catch { return null; }
}

async function saveTgChatId(chatId) {
  if (!storageKey) return;
  localStorage.setItem(LS_TG_CHAT_ID, await encryptStr(storageKey, String(chatId)));
}

async function loadTgChatId() {
  if (!storageKey) return null;
  const raw = localStorage.getItem(LS_TG_CHAT_ID);
  if (!raw) return null;
  try   { return parseInt(await decryptStr(storageKey, raw)); }
  catch { return null; }
}

async function saveTgGroupId(groupId) {
  if (!storageKey) return;
  localStorage.setItem(LS_TG_GROUP_ID, await encryptStr(storageKey, String(groupId)));
}

async function loadTgGroupId() {
  if (!storageKey) return null;
  const raw = localStorage.getItem(LS_TG_GROUP_ID);
  if (!raw) return null;
  try   { return parseInt(await decryptStr(storageKey, raw)); }
  catch { return null; }
}

// ────────────────────────────────────────────────────────────
// Telegram — API
// ────────────────────────────────────────────────────────────
async function tgApi(method, params = {}, signal = null) {
  if (!tgToken) throw new Error('token não configurado');
  const opts = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  };
  if (signal) opts.signal = signal;
  const res  = await fetch(`https://api.telegram.org/bot${tgToken}/${method}`, opts);
  const json = await res.json();
  if (!json.ok) throw new Error(json.description || `${method} falhou`);
  return json.result;
}

async function tgApiForm(method, formData, signal = null) {
  if (!tgToken) throw new Error('token não configurado');
  const opts = { method: 'POST', body: formData };
  if (signal) opts.signal = signal;
  const res  = await fetch(`https://api.telegram.org/bot${tgToken}/${method}`, opts);
  const json = await res.json();
  if (!json.ok) throw new Error(json.description || `${method} falhou`);
  return json.result;
}

// ────────────────────────────────────────────────────────────
// Telegram — wizard helpers
// ────────────────────────────────────────────────────────────
function _tgStep(n)  { return document.getElementById('tg-wstep-' + n); }
function _tgBody(n)  { return document.getElementById('tg-wbody-' + n); }
function _tgNum(n)   { return document.getElementById('tg-wnum-'  + n); }
function _tgVal(n)   { return document.getElementById('tg-wval-'  + n); }

function activateTgStep(n) {
  const step = _tgStep(n), body = _tgBody(n);
  if (!step) return;
  step.classList.remove('tg-wstep--locked', 'tg-wstep--done');
  if (body) body.style.display = '';
}

function completeTgStep(n, val) {
  const step = _tgStep(n), body = _tgBody(n), num = _tgNum(n), valEl = _tgVal(n);
  if (!step) return;
  step.classList.remove('tg-wstep--locked');
  step.classList.add('tg-wstep--done');
  if (num)   num.textContent = '✓';
  if (valEl && val) valEl.textContent = val;
  if (body)  body.style.display = 'none';
}

function toggleTgStep(n) {
  const step = _tgStep(n);
  if (!step || step.classList.contains('tg-wstep--locked')) return;
  const body = _tgBody(n);
  if (body) body.style.display = body.style.display === 'none' ? '' : 'none';
}

function resetTgWizard() {
  for (let i = 1; i <= 3; i++) {
    const step = _tgStep(i), body = _tgBody(i), num = _tgNum(i), valEl = _tgVal(i);
    if (!step) continue;
    step.classList.remove('tg-wstep--done');
    if (i === 1) {
      step.classList.remove('tg-wstep--locked');
      if (body) body.style.display = '';
    } else {
      step.classList.add('tg-wstep--locked');
      if (body) body.style.display = 'none';
    }
    if (num)   num.textContent = String(i);
    if (valEl) valEl.textContent = '';
  }
  const chatidRow = document.getElementById('tg-chatid-row');
  if (chatidRow) chatidRow.style.display = 'none';
  const resetBtn = document.getElementById('btn-tg-reset');
  if (resetBtn) resetBtn.style.display = 'none';
  document.getElementById('tg-connect-row').style.display = 'none';
}

// ────────────────────────────────────────────────────────────
// Telegram — guide modal
// ────────────────────────────────────────────────────────────
function openTgGuide() {
  document.getElementById('tg-modal-backdrop').style.display = '';
  document.getElementById('tg-modal').style.display = '';
  document.body.style.overflow = 'hidden';
}

function closeTgGuide() {
  document.getElementById('tg-modal-backdrop').style.display = 'none';
  document.getElementById('tg-modal').style.display = 'none';
  document.body.style.overflow = '';
}

// ────────────────────────────────────────────────────────────
// Telegram — configuration UI
// ────────────────────────────────────────────────────────────
function setTgMsg(msg, isError = false) {
  const el = document.getElementById('tg-status-msg');
  if (!el) return;
  el.textContent = msg;
  el.style.display = msg ? '' : 'none';
  el.className = 'tg-status-msg' + (isError ? ' error' : '');
}

async function configureTelegram() {
  const tokenInput = document.getElementById('tg-token-input');
  const token = tokenInput.value.trim();
  if (!token) return;

  document.getElementById('btn-tg-config').disabled = true;
  setTgMsg('validando token…');

  const prevToken = tgToken;
  tgToken = token;
  try {
    const bot = await tgApi('getMe');
    debugLog('info', `TG bot: @${bot.username}`);
    await saveTgToken(token);
    tokenInput.value = '';
    setTgMsg('');
    completeTgStep(1, '@' + bot.username);
    activateTgStep(2);
    await discoverTgChatId(bot.username);
  } catch (e) {
    debugLog('error', `TG config: ${e.message}`);
    setTgMsg('Token inválido: ' + e.message, true);
    tgToken = prevToken;
  }
  document.getElementById('btn-tg-config').disabled = false;
}

function setDiscoverMsg(msg, isDiscovering = false) {
  const el = document.getElementById('tg-discover-msg');
  if (!el) return;
  el.innerHTML = msg;
  el.className = 'tg-discover-status' + (isDiscovering ? ' discovering' : '');
}

async function discoverTgChatId(botUsername) {
  // Flush old updates: find latest update_id without long-polling
  let offset = 0;
  try {
    const flush = await tgApi('getUpdates', { offset: -1, limit: 1 });
    if (flush.length > 0) offset = flush[flush.length - 1].update_id + 1;
  } catch {}

  const TIMEOUT_MS = 120000;
  _discoverAbortCtrl = new AbortController();
  const signal   = _discoverAbortCtrl.signal;
  const deadline = Date.now() + TIMEOUT_MS;

  const tickMsg = () => {
    const remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    setDiscoverMsg(
      `Aguardando mensagem ao <strong>@${botUsername}</strong> no Telegram… ${remaining}s`,
      true
    );
  };
  tickMsg();
  const tickInterval = setInterval(tickMsg, 1000);

  try {
    while (Date.now() < deadline) {
      try {
        const updates = await tgApi('getUpdates', { offset, timeout: 20, limit: 10 }, signal);
        for (const u of updates) {
          offset = u.update_id + 1;
          const msg = u.message || u.channel_post;
          if (msg && msg.chat) {
            myTgChatId   = msg.chat.id;
            tgPollOffset = offset;
            await saveTgChatId(myTgChatId);
            _discoverAbortCtrl = null;
            applyTgConfiguredUI();
            debugLog('info', `TG chat_id=${myTgChatId}`);
            return;
          }
        }
      } catch (e) {
        if (e.name === 'AbortError') return;
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  } finally {
    clearInterval(tickInterval);
  }

  setDiscoverMsg('Tempo esgotado. Envie uma mensagem ao bot e tente novamente.');
  _discoverAbortCtrl = null;
}

function applyTgConfiguredUI() {
  // Mark step 1 done (token already set)
  const tgStep1 = _tgStep(1);
  if (tgStep1 && !tgStep1.classList.contains('tg-wstep--done')) {
    completeTgStep(1, tgToken ? '●●●●●●' : '');
  }

  // Complete step 2 with chat ID
  const chatIdEl = document.getElementById('tg-my-chat-id');
  if (chatIdEl) chatIdEl.textContent = String(myTgChatId);
  const chatidRow = document.getElementById('tg-chatid-row');
  if (chatidRow) chatidRow.style.display = '';
  setDiscoverMsg('');
  completeTgStep(2, String(myTgChatId));

  // Activate or complete step 3 depending on whether group is already saved
  if (tgGroupId) {
    const grpInp = document.getElementById('tg-group-input');
    if (grpInp && !grpInp.value.trim()) grpInp.value = String(tgGroupId);
    completeTgStep(3, String(tgGroupId));
  } else {
    activateTgStep(3);
  }

  // Show reset button and peer TG chat input in connect form
  const resetBtn = document.getElementById('btn-tg-reset');
  if (resetBtn) resetBtn.style.display = '';
  document.getElementById('tg-connect-row').style.display = '';

  updateQR();
  updateTgBtnVisibility();
}

async function saveTgGroupFromInput() {
  const grpInp = document.getElementById('tg-group-input');
  const val = grpInp && parseInt(grpInp.value.trim());
  if (!val) { showToast('Informe um ID de grupo válido.'); return; }
  tgGroupId = val;
  await saveTgGroupId(tgGroupId);
  completeTgStep(3, String(tgGroupId));
  updateQR();
  updateTgBtnVisibility();
  debugLog('info', `TG group relay saved: ${tgGroupId}`);
  showToast('Grupo relay salvo.');
}

function resetTelegram() {
  if (!confirm('Remover configuração do Telegram?')) return;
  localStorage.removeItem(LS_TG_TOKEN);
  localStorage.removeItem(LS_TG_CHAT_ID);
  localStorage.removeItem(LS_TG_GROUP_ID);
  tgToken    = null;
  myTgChatId = null;
  tgGroupId  = null;
  stopTgPolling();
  document.getElementById('tg-token-input').value = '';
  resetTgWizard();
  updateQR();
  updateTgBtnVisibility();
}

function copyTgChatId() {
  if (!myTgChatId) return;
  navigator.clipboard.writeText(String(myTgChatId)).then(() => {
    const btn = document.getElementById('btn-tg-copy');
    const prev = btn.textContent;
    btn.textContent = 'copiado!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = prev; btn.classList.remove('copied'); }, 2200);
  }).catch(() => showToast('Não foi possível copiar.'));
}

// ────────────────────────────────────────────────────────────
// Telegram — relay
// ────────────────────────────────────────────────────────────
async function startTgPolling() {
  stopTgPolling();
  tgAbortCtrl = new AbortController();
  const signal = tgAbortCtrl.signal;
  debugLog('info', `TG polling started · offset=${tgPollOffset}`);

  while (tgMode) {
    try {
      const updates = await tgApi('getUpdates', { offset: tgPollOffset, timeout: 25, limit: 10 }, signal);
      for (const u of updates) {
        tgPollOffset = u.update_id + 1;
        await handleTgUpdate(u);
      }
    } catch (e) {
      if (e.name === 'AbortError') break;
      debugLog('error', `TG poll: ${e.message}`);
      if (tgMode) await new Promise(r => setTimeout(r, 3000));
    }
  }
  debugLog('info', 'TG polling stopped');
}

function stopTgPolling() {
  if (tgAbortCtrl)       { tgAbortCtrl.abort();       tgAbortCtrl       = null; }
  if (_discoverAbortCtrl){ _discoverAbortCtrl.abort(); _discoverAbortCtrl = null; }
}

async function handleTgUpdate(update) {
  const msg = update.message || update.channel_post;
  if (!msg) return;

  // When a relay group/channel is configured, only process messages from it.
  // Without a group, fall back to filtering by peer's personal chat (legacy path —
  // getUpdates does not return bot→user messages, so downloads won't trigger automatically).
  const expectedChatId = tgGroupId || peerTgChatId;
  if (expectedChatId && msg.chat.id !== expectedChatId) return;
  if (!channelKey) return;

  try {
    if (msg.text) {
      const envelope = JSON.parse(msg.text);
      if (!envelope.relay || envelope.v !== 1) return;
      if (envelope.from === myId) return;  // ignore own relay messages echoed back from group
      const data = JSON.parse(await decryptStr(channelKey, envelope.payload));
      await handleData(data, true);
    }

    if (msg.document) {
      const caption = JSON.parse(msg.caption || '{}');
      if (!caption.relay || caption.v !== 1) return;
      if (caption.from === myId) return;  // ignore own file echoed back from group

      const fileInfo = await tgApi('getFile', { file_id: msg.document.file_id });
      const res      = await fetch(`https://api.telegram.org/file/bot${tgToken}/${fileInfo.file_path}`);
      if (!res.ok) throw new Error('download falhou');

      const encBuf   = await res.arrayBuffer();
      const decBytes = await decryptBytes(channelKey, new Uint8Array(encBuf));

      const blob = new Blob([decBytes]);
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = caption.name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);

      await pushHistory({ type: 'file', name: caption.name, size: caption.size, direction: 'received', timestamp: Date.now() });
      debugLog('info', `TG file received: ${caption.name} (${fmtBytes(caption.size)})`);
    }
  } catch (e) {
    debugLog('error', `handleTgUpdate: ${e.message}`);
  }
}

async function tgSend(data) {
  if (!channelKey || !tgToken) return;
  const relayChatId = tgGroupId || peerTgChatId;
  if (!relayChatId) return;
  const payload = await encryptStr(channelKey, JSON.stringify(data));
  await tgApi('sendMessage', {
    chat_id: relayChatId,
    text: JSON.stringify({ relay: true, v: 1, from: myId, payload })
  });
}

async function tgSendFile(file) {
  if (!channelKey || !tgToken) return;
  const relayChatId = tgGroupId || peerTgChatId;
  if (!relayChatId) return;
  if (file.size > TG_MAX_FILE) {
    showToast('Arquivo muito grande para relay Telegram (máx. 50 MB)');
    return;
  }

  const fileId = uid();
  makeProgressItem(fileId, file.name, file.size);
  setProgress(fileId, 0.1);

  const buf       = await file.arrayBuffer();
  setProgress(fileId, 0.3);
  const encrypted = await encryptBytes(channelKey, new Uint8Array(buf));
  setProgress(fileId, 0.5);

  const caption  = JSON.stringify({ relay: true, v: 1, from: myId, name: file.name, size: file.size });
  const formData = new FormData();
  formData.append('chat_id', String(relayChatId));
  formData.append('document', new Blob([encrypted], { type: 'application/octet-stream' }), file.name + '.enc');
  formData.append('caption', caption);

  await tgApiForm('sendDocument', formData);
  donProgress(fileId);
  await pushHistory({ type: 'file', name: file.name, size: file.size, direction: 'sent', timestamp: Date.now() });
  debugLog('info', `TG file sent: ${file.name} via ${tgGroupId ? 'group relay' : 'personal chat'}`);
}

async function switchToTgMode() {
  // Read peer's TG chat ID from input if not yet parsed
  if (!peerTgChatId) {
    const inp = document.getElementById('tg-chat-input');
    if (inp && inp.value.trim()) peerTgChatId = parseInt(inp.value.trim()) || null;
  }
  // Read relay group ID from input if not yet parsed
  if (!tgGroupId) {
    const grpInp = document.getElementById('tg-group-input');
    if (grpInp && grpInp.value.trim()) {
      tgGroupId = parseInt(grpInp.value.trim()) || null;
      if (tgGroupId) await saveTgGroupId(tgGroupId);
    }
  }

  const pid = lastPeerId || connectTarget || document.getElementById('peer-input').value.trim();
  if (!pid)                    { showToast('Informe o ID do peer antes de usar o relay Telegram.'); return; }
  if (!tgToken || !myTgChatId) { showToast('Configure o Telegram antes de ativar o relay.'); return; }
  if (!tgGroupId && !peerTgChatId) { showToast('Informe o ID do grupo relay ou o chat ID do peer.'); return; }
  if (!tgGroupId) {
    showToast('Sem grupo relay: arquivos não serão baixados automaticamente. Configure um grupo para relay completo.');
  }

  debugLog('info', `switching to TG relay · peer=${pid}`);

  // Stop P2P gracefully without triggering auto-reconnect
  stopHeartbeat();
  if (conn) { const c = conn; conn = null; c.close(); }
  connectTarget  = null;
  connectRetries = 0;

  // Derive channel key from both peer IDs (same formula as P2P)
  if (!channelKey) {
    channelKey = await deriveKey([myId, pid].sort().join(':'), SALT_CHANNEL);
    debugLog('info', 'TG channel key derived');
  }

  lastPeerId = pid;
  tgMode     = true;
  persistLastPeer();

  // Sync offset to avoid replaying old messages
  try {
    const latest = await tgApi('getUpdates', { offset: -1, limit: 1 });
    if (latest.length > 0) tgPollOffset = latest[latest.length - 1].update_id + 1;
  } catch {}

  startTgPolling();

  const short = pid.length > 16 ? pid.slice(0, 14) + '…' : pid;
  document.getElementById('peer-id-badge').textContent = short;
  document.getElementById('connection-badge').classList.add('visible', 'tg-mode');
  document.getElementById('connect-form').style.display = 'none';
  document.getElementById('transfer-section').classList.add('visible');
  document.getElementById('btn-connect').disabled = false;
  setStatus('connected', 'telegram');
  updateTgBtnVisibility();
  showToast('Relay Telegram ativado');
}

function updateTgBtnVisibility() {
  const chatInp   = document.getElementById('tg-chat-input');
  const grpInp    = document.getElementById('tg-group-input');
  const chatReady = peerTgChatId || (chatInp && parseInt(chatInp.value.trim()));
  const grpReady  = tgGroupId || (grpInp && parseInt(grpInp.value.trim()));
  const ready     = !!(tgToken && myTgChatId && (chatReady || grpReady) && !tgMode);
  const btn       = document.getElementById('btn-use-tg');
  if (btn) btn.style.display = ready ? '' : 'none';
}

// ────────────────────────────────────────────────────────────
// QR code
// ────────────────────────────────────────────────────────────
function buildQRUrl() {
  const base = `${location.origin}${location.pathname}?connect=${encodeURIComponent(myId)}`;
  let url = myTgChatId ? base + `&tgchat=${myTgChatId}` : base;
  if (tgGroupId) url += `&tggroup=${tgGroupId}`;
  return url;
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

    // Load Telegram config (requires storageKey)
    const savedToken   = await loadTgToken();
    const savedChatId  = await loadTgChatId();
    const savedGroupId = await loadTgGroupId();
    if (savedToken)  { tgToken    = savedToken; debugLog('info', 'TG token loaded'); }
    if (savedGroupId){ tgGroupId  = savedGroupId; debugLog('info', `TG group relay id=${tgGroupId}`); }
    if (savedChatId) {
      myTgChatId = savedChatId;
      applyTgConfiguredUI();
    }

    updateQR();
    setStatus('ready', 'pronto');

    // Parse URL params
    const p       = new URLSearchParams(location.search);
    const cid     = p.get('connect');
    const tgchat  = p.get('tgchat');
    const tggroup = p.get('tggroup');
    if (tgchat) {
      peerTgChatId = parseInt(tgchat);
      const inp = document.getElementById('tg-chat-input');
      if (inp) inp.value = tgchat;
    }
    if (tggroup) {
      tgGroupId = parseInt(tggroup);
      const grpInp = document.getElementById('tg-group-input');
      if (grpInp) grpInp.value = tggroup;
      await saveTgGroupId(tgGroupId);
      debugLog('info', `TG group relay from URL: ${tgGroupId}`);
    }
    if (tgchat || tggroup) updateTgBtnVisibility();
    if (cid && cid !== id) {
      document.getElementById('peer-input').value = cid;
      connectToPeer();
    } else if (!cid) {
      // Restore last peer (persists across page reloads, cleared on manual disconnect)
      const savedPeer   = localStorage.getItem(LS_LAST_PEER);
      const savedPeerTg = localStorage.getItem(LS_PEER_TG_CHAT);
      if (savedPeer && savedPeer !== id) {
        document.getElementById('peer-input').value = savedPeer;
        if (savedPeerTg && !peerTgChatId) {
          peerTgChatId = parseInt(savedPeerTg);
          const inp = document.getElementById('tg-chat-input');
          if (inp) inp.value = savedPeerTg;
          updateTgBtnVisibility();
        }
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

    const serverErrors = ['network', 'server-error', 'socket-error', 'socket-closed'];
    if (serverErrors.includes(err.type)) {
      const detail = err.message ? err.message.split('\n')[0].slice(0, 50) : err.type;
      setStatus('error', detail);
      showToast(`Erro de rede: ${err.type}`);
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

    const msg = err.type === 'peer-unavailable'
      ? `ID não encontrado após ${MAX_RETRIES + 1} tentativas`
      : err.message || err.type || 'erro de conexão';
    connectTarget  = null;
    connectRetries = 0;
    setStatus('ready', 'pronto');
    showToast('Erro: ' + msg);
    document.getElementById('btn-connect').disabled = false;
  });
}

function connectToPeer() {
  const tid = document.getElementById('peer-input').value.trim();
  if (!tid || !peer || !myId) return;
  if (tid === myId) { showToast('Esse é o seu próprio ID.'); return; }

  // Read peer's TG chat ID if provided
  const tgInp = document.getElementById('tg-chat-input');
  if (tgInp && tgInp.value.trim()) {
    peerTgChatId = parseInt(tgInp.value.trim()) || null;
    updateTgBtnVisibility();
  }

  if (conn && conn.open && conn.peer === tid) {
    debugLog('info', `already connected to ${tid}`);
    return;
  }

  connectTarget  = tid;
  connectRetries = 0;
  doConnect();
}

function doConnect() {
  const tid = connectTarget;
  if (!tid || !peer || !myId) return;

  const label = connectRetries > 0 ? ` (tentativa ${connectRetries + 1}/${MAX_RETRIES + 1})` : '';
  debugLog('conn', `connecting to ${tid}${label}`);
  setStatus('connecting', connectRetries > 0 ? `reconectando… ${connectRetries + 1}` : 'conectando…');
  document.getElementById('btn-connect').disabled = true;

  if (conn) { conn.close(); conn = null; }
  conn = peer.connect(tid, { reliable: true });
  setupConn();
}

function hookICE(c) {
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
        if (tgToken && myTgChatId && peerTgChatId && !tgMode) {
          setTimeout(switchToTgMode, 1000);
        }
      }
    });
    pc.addEventListener('icegatheringstatechange', () => {
      debugLog('conn', `ICE gathering → ${pc.iceGatheringState}`);
    });
    pc.addEventListener('connectionstatechange', () => {
      debugLog('conn', `RTC → ${pc.connectionState}`);
    });
  })();
}

function setupConn() {
  hookICE(conn);

  const _connTimeout = setTimeout(() => {
    debugLog('error', 'connection timeout (20s) — ICE negotiation stalled');
    showToast('Tempo esgotado: verifique a rede ou bloqueio de firewall');
    if (tgToken && myTgChatId && peerTgChatId && !tgMode) {
      setTimeout(switchToTgMode, 500);
    }
  }, 20000);

  conn.on('open', async () => {
    clearTimeout(_connTimeout);
    connectTarget  = null;
    connectRetries = 0;
    const pid  = conn.peer;
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
    updateTgBtnVisibility();
  });

  conn.on('data', data => handleData(data, false));

  conn.on('close', () => {
    clearTimeout(_connTimeout);
    stopHeartbeat();
    debugLog('conn', 'closed');
    const target = lastPeerId;
    onDisconnected();
    if (target) scheduleReconnect(target);
  });

  conn.on('error', e => {
    clearTimeout(_connTimeout);
    stopHeartbeat();
    debugLog('error', `conn · ${e.message || e.type || String(e)}`);
    const target = lastPeerId;
    onDisconnected();
    if (target) scheduleReconnect(target);
  });
}

function onDisconnected() {
  debugLog('info', 'state reset · waiting for connection');
  stopHeartbeat();
  stopTgPolling();
  connectTarget  = null;
  connectRetries = 0;
  tgMode         = false;
  setStatus('ready', 'pronto');
  document.getElementById('connection-badge').classList.remove('visible', 'tg-mode');
  document.getElementById('connect-form').style.display = '';
  document.getElementById('transfer-section').classList.remove('visible');
  document.getElementById('transfers-list').innerHTML = '';
  channelKey = null;
  conn       = null;
  incoming   = {};
  sendQueue  = [];
  isSending  = false;
  updateTgBtnVisibility();
}

function disconnect() {
  lastPeerId = null; // manual disconnect — don't auto-reconnect
  clearLastPeer();
  stopHeartbeat();
  stopTgPolling();
  tgMode = false;
  if (conn) { conn.close(); }
  onDisconnected();
}

// ────────────────────────────────────────────────────────────
// Incoming data
// ────────────────────────────────────────────────────────────
async function handleData(data, fromTg = false) {
  try {
    if (data.type === 'ping') {
      if (!tgMode) conn.send({ type: 'pong', ts: data.ts });
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
      f.chunks[data.index] = fromB64(data.data);
      f.received++;
      setProgress(data.fileId, f.received / f.meta.totalChunks);
      if (f.received === f.meta.totalChunks) assembleAndDownload(data.fileId);
      return;
    }

    if (data.type === 'message') {
      let text = data.text;
      // TG payloads are already decrypted; P2P payloads need decryption
      if (!fromTg && channelKey) {
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
  if ((!conn && !tgMode) || !files.length) return;
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
  while (sendQueue.length && (conn || tgMode)) {
    const file = sendQueue.shift();
    if (tgMode) {
      await tgSendFile(file);
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
  if (!text || (!conn && !tgMode)) return;

  if (tgMode) {
    await tgSend({ type: 'message', text, ts: Date.now() });
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

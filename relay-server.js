'use strict';
const { WebSocketServer } = require('ws');
const PORT = process.env.PORT || 8765;

// rooms: Map<roomId, { a: ws, aPeerId: string, b?: ws, bPeerId?: string }>
const rooms = new Map();

const wss = new WebSocketServer({ port: PORT });
console.log(`relay-server listening on ws://localhost:${PORT}`);

wss.on('connection', ws => {
  ws._roomId  = null;
  ws._peerId  = null;
  ws._slot    = null; // 'a' | 'b'

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'join')  { handleJoin(ws, msg);  return; }
    if (msg.type === 'relay') { handleRelay(ws);       return; } // forward verbatim
    if (msg.type === 'pong')  { return; }

    // forward relay messages verbatim (forward raw buffer, not reparsed)
  });

  // For relay type, we need the raw buffer — handle separately
  ws._rawHandler = raw => {
    try {
      const str = raw.toString();
      const peek = JSON.parse(str);
      if (peek.type === 'relay') {
        const partner = getPartner(ws);
        if (partner && partner.readyState === 1) partner.send(str);
      }
    } catch {}
  };
  ws.removeAllListeners('message');

  ws.on('message', raw => {
    let msg;
    const str = raw.toString();
    try { msg = JSON.parse(str); } catch { return; }

    if (msg.type === 'join')  { handleJoin(ws, msg); return; }
    if (msg.type === 'pong')  { return; }
    if (msg.type === 'relay') {
      const partner = getPartner(ws);
      if (partner && partner.readyState === 1) partner.send(str);
      return;
    }
  });

  ws.on('close', () => handleLeave(ws));
  ws.on('error', () => handleLeave(ws));
});

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function getPartner(ws) {
  if (!ws._roomId) return null;
  const room = rooms.get(ws._roomId);
  if (!room) return null;
  return ws._slot === 'a' ? room.b : room.a;
}

function handleJoin(ws, msg) {
  const { room: roomId, peerId } = msg;
  if (!roomId || !peerId) return;

  if (rooms.has(roomId)) {
    const room = rooms.get(roomId);
    if (room.b) {
      send(ws, { type: 'error', code: 'room-full' });
      ws.close();
      return;
    }
    // Reject self-pairing: same peer joining both slots
    if (room.aPeerId === peerId) {
      send(ws, { type: 'error', code: 'self-join' });
      ws.close();
      return;
    }
    room.b       = ws;
    room.bPeerId = peerId;
    ws._roomId   = roomId;
    ws._peerId   = peerId;
    ws._slot     = 'b';
    send(ws,     { type: 'joined', peerPeerId: room.aPeerId });
    send(room.a, { type: 'joined', peerPeerId: peerId });
    console.log(`[room ${roomId.slice(0,12)}…] paired  a=${room.aPeerId} b=${peerId}`);
  } else {
    rooms.set(roomId, { a: ws, aPeerId: peerId });
    ws._roomId = roomId;
    ws._peerId = peerId;
    ws._slot   = 'a';
    send(ws, { type: 'waiting' });
    console.log(`[room ${roomId.slice(0,12)}…] waiting a=${peerId}`);
  }
}

function handleLeave(ws) {
  if (!ws._roomId) return;
  const roomId = ws._roomId;
  const room   = rooms.get(roomId);
  if (!room) return;

  const partner = getPartner(ws);
  if (partner && partner.readyState === 1) {
    send(partner, { type: 'peer-left' });
    // keep partner's slot so it can reconnect into a new room
    partner._roomId = null;
    partner._slot   = null;
  }

  rooms.delete(roomId);
  ws._roomId = null;
  console.log(`[room ${roomId.slice(0,12)}…] closed  by=${ws._peerId}`);
}

// keepalive ping every 30 s
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'ping' }));
  });
}, 30000);

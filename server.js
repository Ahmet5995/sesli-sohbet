// Sinyal sunucusu: odaları yönetir, WebRTC bağlantı mesajlarını iletir.
// Ses sunucudan geçmez; kullanıcılar birbirine doğrudan bağlanır (P2P mesh).
const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const CHANNELS = ['Genel', 'Oyun', 'Müzik', 'Sohbet'];
const clients = new Map(); // id -> { ws, name, channel }
let nextId = 1;
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';
const RANK = { user: 0, mod: 1, admin: 2 };

const server = http.createServer((req, res) => {
  fs.readFile(path.join(__dirname, 'public', 'index.html'), (err, data) => {
    if (err) { res.writeHead(500); return res.end('index.html bulunamadı'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(data);
  });
});

const send = (ws, m) => ws.readyState === 1 && ws.send(JSON.stringify(m));

function roster() {
  const r = {};
  CHANNELS.forEach(c => (r[c] = []));
  for (const [id, c] of clients) if (c.channel) r[c.channel].push({ id, name: c.name, role: c.role });
  return r;
}
function broadcastRoster() {
  const m = { type: 'roster', roster: roster() };
  for (const c of clients.values()) send(c.ws, m);
}
function leave(id) {
  const me = clients.get(id);
  if (!me || !me.channel) return;
  const ch = me.channel;
  me.channel = null;
  for (const o of clients.values()) if (o.channel === ch) send(o.ws, { type: 'peer-left', id });
}

const wss = new WebSocketServer({ server });
wss.on('connection', ws => {
  const id = nextId++;
  clients.set(id, { ws, name: 'Misafir', channel: null, role: 'user' });
  send(ws, { type: 'hello', id, channels: CHANNELS, roster: roster() });

  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    const me = clients.get(id);
    if (m.type === 'join' && CHANNELS.includes(m.channel)) {
      leave(id);
      me.name = String(m.name || 'Misafir').slice(0, 20);
      if (m.key && m.key === ADMIN_KEY) {
        if (me.role !== 'admin') { me.role = 'admin'; send(ws, { type: 'role', role: 'admin' }); }
      } else if (m.key) send(ws, { type: 'notice', text: 'Yönetici şifresi yanlış.' });
      const peers = [...clients].filter(([, c]) => c.channel === m.channel).map(([pid]) => pid);
      me.channel = m.channel;
      send(ws, { type: 'joined', channel: m.channel, peers });
      broadcastRoster();
    } else if (m.type === 'mod') {
      const t = clients.get(m.target);
      if (!t || t === me) return;
      const mine = RANK[me.role];
      if (m.action === 'promote' || m.action === 'demote') {
        if (me.role !== 'admin' || t.role === 'admin') return;
        t.role = m.action === 'promote' ? 'mod' : 'user';
        send(t.ws, { type: 'role', role: t.role });
        broadcastRoster();
      } else if (mine >= 1 && mine > RANK[t.role] && t.channel && t.channel === me.channel) {
        if (m.action === 'kick') {
          leave(m.target); send(t.ws, { type: 'kicked' }); broadcastRoster();
        } else if (m.action === 'mute' || m.action === 'unmute') {
          send(t.ws, { type: 'force-mute', on: m.action === 'mute' });
        }
      }
    } else if (m.type === 'leave') {
      leave(id); broadcastRoster();
    } else if (m.type === 'signal') {
      const t = clients.get(m.to);
      if (t && t.channel && t.channel === me.channel) send(t.ws, { type: 'signal', from: id, data: m.data });
    }
  });
  ws.on('close', () => { leave(id); clients.delete(id); broadcastRoster(); });
});

server.listen(process.env.PORT || 3000, () => console.log('Çalışıyor: http://localhost:' + (process.env.PORT || 3000)));

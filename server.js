// Hesaplar + kalıcı veri (Postgres) + oda yönetimi + WebRTC sinyalleşme.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const util = require('util');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');

const scrypt = util.promisify(crypto.scrypt);
const CHANNELS = ['Genel', 'Oyun', 'Müzik', 'Sohbet', 'AFK'];
const AFK_ID = 'AFK';
const AFK_MS = (Number(process.env.AFK_MINUTES) || 30) * 60000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) console.warn('UYARI: SESSION_SECRET ayarlı değil; sunucu yeniden başlayınca herkes tekrar giriş yapmak zorunda kalır.');
if (!process.env.DATABASE_URL) { console.error('HATA: DATABASE_URL ayarlı değil.'); process.exit(1); }
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
const RANK = { user: 0, mod: 1, admin: 2 };
const users = new Map(); // kullanıcı id -> { name, role, tag } (tüm kayıtlı üyeler)
const chNames = {}; // kanal kimliği -> görünen ad (veritabanında saklanır)

async function initDb() {
  await db.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT NOT NULL, pass TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', tag TEXT NOT NULL DEFAULT '')`);
  await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username))`);
  await db.query(`CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, channel TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL, tag TEXT NOT NULL, text TEXT NOT NULL, time BIGINT NOT NULL)`);
  await db.query(`CREATE INDEX IF NOT EXISTS messages_channel_id ON messages (channel, id)`);
  await db.query(`CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, name TEXT NOT NULL)`);
  await db.query('ALTER TABLE channels ADD COLUMN IF NOT EXISTS seq SERIAL');
  await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT false');
  const cnt = await db.query('SELECT COUNT(*)::int AS n FROM channels');
  if (cnt.rows[0].n === 0) for (const c of ['Genel', 'Oyun', 'Müzik', 'Sohbet']) await db.query('INSERT INTO channels (id, name) VALUES ($1, $1)', [c]);
  await db.query("INSERT INTO channels (id, name) VALUES ('AFK', 'AFK') ON CONFLICT (id) DO NOTHING");
  const cr = await db.query('SELECT id, name FROM channels ORDER BY seq');
  CHANNELS.length = 0;
  cr.rows.filter(x => x.id !== AFK_ID).forEach(x => CHANNELS.push(x.id));
  CHANNELS.push(AFK_ID);
  cr.rows.forEach(x => (chNames[x.id] = x.name));
  const ur = await db.query('SELECT id, username, role, tag, banned FROM users');
  ur.rows.forEach(x => users.set(x.id, { name: x.username, role: x.role, tag: x.tag, banned: x.banned }));
}

// --- Şifre ve oturum ---
async function hash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + (await scrypt(pw, salt, 64)).toString('hex');
}
async function verify(pw, stored) {
  const [salt, h] = String(stored).split(':');
  const a = Buffer.from(h, 'hex'), b = await scrypt(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const makeToken = uid => { const p = uid + '.' + (Date.now() + 30 * 86400000); return p + '.' + sign(p); };
function readToken(t) {
  const [uid, exp, sig] = String(t || '').split('.');
  if (!uid || !exp || !sig || sig.length !== 64) return null;
  const ok = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(uid + '.' + exp)));
  return ok && Number(exp) > Date.now() ? Number(uid) : null;
}

// --- HTTP: sayfa + giriş/kayıt ---
const attempts = new Map();
setInterval(() => attempts.clear(), 3600000);
const limited = ip => {
  const now = Date.now(), a = (attempts.get(ip) || []).filter(t => now - t < 300000);
  a.push(now); attempts.set(ip, a);
  return a.length > 15;
};
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

async function handleAuth(req, res) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (limited(ip)) return json(res, 429, { error: 'Çok fazla deneme. Birkaç dakika sonra tekrar dene.' });
  let body = '';
  for await (const ch of req) { body += ch; if (body.length > 2000) return json(res, 413, { error: 'İstek çok büyük.' }); }
  let d; try { d = JSON.parse(body); } catch { return json(res, 400, { error: 'Geçersiz istek.' }); }
  const username = String(d.username || '').trim(), password = String(d.password || ''), key = String(d.key || '');
  try {
    if (req.url === '/api/register') {
      if (!/^[\p{L}\p{N}_]{3,16}$/u.test(username)) return json(res, 400, { error: 'Kullanıcı adı 3-16 karakter olmalı (harf, rakam, _).' });
      if (password.length < 6 || password.length > 100) return json(res, 400, { error: 'Şifre en az 6 karakter olmalı.' });
      if (key && key !== ADMIN_KEY) return json(res, 400, { error: 'Yönetici şifresi yanlış.' });
      try {
        const r = await db.query('INSERT INTO users (username, pass, role) VALUES ($1, $2, $3) RETURNING id', [username, await hash(password), key ? 'admin' : 'user']);
        users.set(r.rows[0].id, { name: username, role: key ? 'admin' : 'user', tag: '' });
        scheduleMembers();
        return json(res, 200, { token: makeToken(r.rows[0].id) });
      } catch (e) {
        if (e.code === '23505') return json(res, 400, { error: 'Bu kullanıcı adı alınmış.' });
        throw e;
      }
    }
    const r = await db.query('SELECT id, pass, banned FROM users WHERE lower(username) = lower($1)', [username]);
    const u = r.rows[0];
    if (!u || !(await verify(password, u.pass))) return json(res, 400, { error: 'Kullanıcı adı veya şifre hatalı.' });
    if (u.banned) return json(res, 403, { error: 'Bu hesap yasaklandı.' });
    if (key) {
      if (key !== ADMIN_KEY) return json(res, 400, { error: 'Yönetici şifresi yanlış.' });
      await db.query("UPDATE users SET role = 'admin' WHERE id = $1", [u.id]);
      if (users.has(u.id)) users.get(u.id).role = 'admin';
    }
    return json(res, 200, { token: makeToken(u.id) });
  } catch (e) {
    console.error(e);
    return json(res, 500, { error: 'Sunucu hatası. Biraz sonra tekrar dene.' });
  }
}

async function handlePassword(req, res) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (limited(ip)) return json(res, 429, { error: 'Çok fazla deneme. Birkaç dakika sonra tekrar dene.' });
  let body = '';
  for await (const ch of req) { body += ch; if (body.length > 2000) return json(res, 413, { error: 'İstek çok büyük.' }); }
  let d; try { d = JSON.parse(body); } catch { return json(res, 400, { error: 'Geçersiz istek.' }); }
  const uid = readToken(d.token);
  if (!uid) return json(res, 401, { error: 'Oturum geçersiz, tekrar giriş yap.' });
  const np = String(d.newPassword || '');
  if (np.length < 6 || np.length > 100) return json(res, 400, { error: 'Yeni şifre en az 6 karakter olmalı.' });
  try {
    const r = await db.query('SELECT pass, banned FROM users WHERE id = $1', [uid]);
    const u = r.rows[0];
    if (!u || u.banned || !(await verify(String(d.oldPassword || ''), u.pass))) return json(res, 400, { error: 'Mevcut şifre hatalı.' });
    await db.query('UPDATE users SET pass = $1 WHERE id = $2', [await hash(np), uid]);
    return json(res, 200, { ok: true });
  } catch (e) { console.error(e); return json(res, 500, { error: 'Sunucu hatası.' }); }
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && (req.url === '/api/login' || req.url === '/api/register')) return handleAuth(req, res);
  if (req.method === 'POST' && req.url === '/api/password') return handlePassword(req, res);
  fs.readFile(path.join(__dirname, 'public', 'index.html'), (err, data) => {
    if (err) { res.writeHead(500); return res.end('index.html bulunamadı'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(data);
  });
});

// --- WebSocket ---
const clients = new Map();
let nextId = 1;
const send = (ws, m) => ws.readyState === 1 && ws.send(JSON.stringify(m));
function roster() {
  const r = {};
  CHANNELS.forEach(c => (r[c] = []));
  for (const [id, c] of clients) if (c.channel && c.uid && r[c.channel]) r[c.channel].push({ id, name: c.name, role: c.role, tag: c.tag, muted: c.muted, deaf: c.deaf });
  return r;
}
function broadcastRoster() {
  const m = { type: 'roster', roster: roster() };
  for (const c of clients.values()) send(c.ws, m);
  scheduleMembers();
}
// Üyeler listesi: tüm kayıtlı kullanıcılar + çevrim içi/dışı durumu
function membersList(isAdmin) {
  const online = new Map();
  for (const c of clients.values()) if (c.uid) online.set(c.uid, c.channel);
  return [...users].filter(([, u]) => isAdmin || !u.banned).map(([uid, u]) => ({ uid, name: u.name, role: u.role, tag: u.tag, banned: !!u.banned, online: online.has(uid), channel: online.get(uid) || null }));
}
let memTimer = null;
function scheduleMembers() {
  if (memTimer) return;
  memTimer = setTimeout(() => {
    memTimer = null;
    const ma = { type: 'members', list: membersList(true) }, mu = { type: 'members', list: membersList(false) };
    for (const c of clients.values()) if (c.uid) send(c.ws, c.role === 'admin' ? ma : mu);
  }, 300);
}
function broadcastChannels() {
  for (const c of clients.values()) send(c.ws, { type: 'channels', names: chNames });
}
function leave(id) {
  const me = clients.get(id);
  if (!me || !me.channel) return;
  const ch = me.channel;
  me.channel = null;
  for (const o of clients.values()) if (o.channel === ch) send(o.ws, { type: 'peer-left', id });
}

async function handle(id, me, m) {
  if (m.type === 'auth') {
    const uid = readToken(m.token);
    const r = uid ? await db.query('SELECT id, username, role, tag, banned FROM users WHERE id = $1', [uid]) : { rows: [] };
    const u = r.rows[0];
    if (!u) return send(me.ws, { type: 'auth-fail' });
    if (u.banned) return send(me.ws, { type: 'auth-fail', reason: 'Bu hesap yasaklandı.' });
    for (const [oid, o] of clients) {
      if (oid !== id && o.uid === u.id) { send(o.ws, { type: 'replaced' }); o.uid = null; o.channel = null; o.ws.close(); }
    }
    Object.assign(me, { uid: u.id, name: u.username, role: u.role, tag: u.tag, lastActive: Date.now() });
    users.set(u.id, { name: u.username, role: u.role, tag: u.tag });
    send(me.ws, { type: 'authed', name: me.name, role: me.role, tag: me.tag });
    send(me.ws, { type: 'members', list: membersList(me.role === 'admin') });
    return scheduleMembers();
  }
  if (!me.uid) return;
  if (m.type !== 'ping' && m.type !== 'signal') me.lastActive = Date.now();
  // AFK'dan otomatik taşınan kişi geri hareket edince eski kanalına döner
  if (m.type === 'activity' || m.type === 'chat' || m.type === 'state') {
    if (me.channel === AFK_ID && me.afkFrom && Date.now() - (me.movedAt || 0) > 5000) {
      const to = me.afkFrom; me.afkFrom = null;
      if (CHANNELS.includes(to)) send(me.ws, { type: 'moved', channel: to, back: true });
    }
  }
  if (m.type === 'activity') return;

  if (m.type === 'join' && CHANNELS.includes(m.channel)) {
    let hist = [];
    try {
      const r = await db.query('SELECT id, name, role, tag, text, time FROM messages WHERE channel = $1 ORDER BY id DESC LIMIT 50', [m.channel]);
      hist = r.rows.reverse().map(x => ({ ...x, time: Number(x.time) }));
    } catch (e) { console.error(e); }
    if (m.channel !== AFK_ID) me.afkFrom = null;
    leave(id);
    const peers = [...clients].filter(([pid, c]) => pid !== id && c.channel === m.channel).map(([pid]) => pid);
    me.channel = m.channel;
    send(me.ws, { type: 'joined', channel: m.channel, peers });
    send(me.ws, { type: 'history', channel: m.channel, messages: hist });
    broadcastRoster();
  } else if (m.type === 'leave') {
    leave(id); broadcastRoster();
  } else if (m.type === 'state') {
    me.muted = !!m.muted; me.deaf = !!m.deaf; broadcastRoster();
  } else if (m.type === 'signal') {
    const t = clients.get(m.to);
    if (t && t.channel && t.channel === me.channel) send(t.ws, { type: 'signal', from: id, data: m.data });
  } else if (m.type === 'chat') {
    if (!me.channel) return;
    const text = String(m.text || '').trim().slice(0, 300);
    const now = Date.now();
    if (!text || now - (me.lastChat || 0) < 700) return;
    me.lastChat = now;
    const ch = me.channel;
    const msg = { name: me.name, role: me.role, tag: me.tag, text, time: now };
    try {
      const r = await db.query('INSERT INTO messages (channel, name, role, tag, text, time) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', [ch, msg.name, msg.role, msg.tag, text, now]);
      msg.id = r.rows[0].id;
    } catch (e) { console.error(e); }
    for (const c of clients.values()) if (c.channel === ch) send(c.ws, { type: 'chat', msg });
  } else if (m.type === 'delmsg') {
    if (me.role !== 'admin') return;
    const mid = Number(m.id) || 0;
    const r = await db.query('DELETE FROM messages WHERE id = $1 RETURNING channel', [mid]);
    if (r.rows[0]) for (const c of clients.values()) if (c.channel === r.rows[0].channel) send(c.ws, { type: 'msgdel', id: mid });
  } else if (m.type === 'ban' || m.type === 'unban') {
    if (me.role !== 'admin') return;
    const uid = Number(m.uid), u = users.get(uid);
    if (!u || u.role === 'admin' || uid === me.uid) return;
    const on = m.type === 'ban';
    await db.query('UPDATE users SET banned = $1 WHERE id = $2', [on, uid]);
    u.banned = on;
    if (on) for (const c of clients.values()) if (c.uid === uid) { send(c.ws, { type: 'banned' }); c.uid = null; c.channel = null; c.ws.close(); }
    broadcastRoster();
  } else if (m.type === 'resetpw') {
    if (me.role !== 'admin') return;
    const uid = Number(m.uid), u = users.get(uid);
    if (!u || u.role === 'admin') return;
    const pw = crypto.randomBytes(5).toString('hex');
    await db.query('UPDATE users SET pass = $1 WHERE id = $2', [await hash(pw), uid]);
    send(me.ws, { type: 'pwreset', name: u.name, password: pw });
  } else if (m.type === 'chcreate') {
    if (me.role !== 'admin' || CHANNELS.length >= 15) return;
    const name = String(m.name || '').replace(/[<>]/g, '').trim().slice(0, 20);
    if (!name) return;
    const cid = 'c' + Date.now().toString(36) + crypto.randomBytes(2).toString('hex');
    await db.query('INSERT INTO channels (id, name) VALUES ($1, $2)', [cid, name]);
    chNames[cid] = name;
    CHANNELS.splice(CHANNELS.indexOf(AFK_ID), 0, cid);
    broadcastChannels(); broadcastRoster();
  } else if (m.type === 'chdelete') {
    if (me.role !== 'admin' || m.channel === AFK_ID || !CHANNELS.includes(m.channel)) return;
    CHANNELS.splice(CHANNELS.indexOf(m.channel), 1);
    const fb = CHANNELS[0];
    await db.query('DELETE FROM channels WHERE id = $1', [m.channel]);
    await db.query('DELETE FROM messages WHERE channel = $1', [m.channel]);
    delete chNames[m.channel];
    for (const [cid, c] of clients) if (c.channel === m.channel) { leave(cid); send(c.ws, { type: 'moved', channel: fb, removed: true }); }
    broadcastChannels(); broadcastRoster();
  } else if (m.type === 'rename') {
    if (me.role !== 'admin' || !CHANNELS.includes(m.channel)) return;
    const name = String(m.name || '').replace(/[<>]/g, '').trim().slice(0, 20);
    if (!name) return;
    chNames[m.channel] = name;
    await db.query('UPDATE channels SET name = $1 WHERE id = $2', [name, m.channel]);
    for (const c of clients.values()) send(c.ws, { type: 'channels', names: chNames });
  } else if (m.type === 'mod') {
    const t = clients.get(m.target);
    if (!t || !t.uid) return;
    if (m.action === 'tag') {
      if (me.role !== 'admin') return;
      t.tag = String(m.tag || '').replace(/[<>]/g, '').trim().slice(0, 12);
      await db.query('UPDATE users SET tag = $1 WHERE id = $2', [t.tag, t.uid]);
      if (users.has(t.uid)) users.get(t.uid).tag = t.tag;
      return broadcastRoster();
    }
    if (t === me) return;
    if (m.action === 'move') {
      if (me.role !== 'admin' || t.role === 'admin' || !t.channel || !CHANNELS.includes(m.channel) || t.channel === m.channel) return;
      return send(t.ws, { type: 'moved', channel: m.channel });
    }
    const mine = RANK[me.role];
    if (m.action === 'promote' || m.action === 'demote') {
      if (me.role !== 'admin' || t.role === 'admin') return;
      t.role = m.action === 'promote' ? 'mod' : 'user';
      await db.query('UPDATE users SET role = $1 WHERE id = $2', [t.role, t.uid]);
      if (users.has(t.uid)) users.get(t.uid).role = t.role;
      send(t.ws, { type: 'role', role: t.role });
      broadcastRoster();
    } else if (mine >= 1 && mine > RANK[t.role] && t.channel && t.channel === me.channel) {
      if (m.action === 'kick') {
        leave(m.target); send(t.ws, { type: 'kicked' }); broadcastRoster();
      } else if (m.action === 'mute' || m.action === 'unmute') {
        send(t.ws, { type: 'force-mute', on: m.action === 'mute' });
      }
    }
  }
}

const wss = new WebSocketServer({ server });
wss.on('connection', ws => {
  const id = nextId++;
  clients.set(id, { ws, uid: null, name: '', channel: null, role: 'user', tag: '', muted: false, deaf: false, lastActive: Date.now() });
  send(ws, { type: 'hello', id, channels: CHANNELS, names: chNames, roster: roster() });
  ws.on('message', async raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    const me = clients.get(id);
    if (!me) return;
    try { await handle(id, me, m); } catch (e) { console.error(e); }
  });
  ws.on('close', () => { leave(id); clients.delete(id); broadcastRoster(); });
});

// Hareketsiz (AFK) kullanıcıları AFK kanalına taşı: her dakika kontrol edilir
setInterval(() => {
  const now = Date.now();
  for (const c of clients.values()) {
    if (c.uid && c.channel && c.channel !== AFK_ID && now - c.lastActive > AFK_MS) {
      c.lastActive = now; c.afkFrom = c.channel; c.movedAt = now;
      send(c.ws, { type: 'moved', channel: AFK_ID, afk: Math.round(AFK_MS / 60000) });
    }
  }
}, 60000);

setInterval(() => db.query('DELETE FROM messages WHERE time < $1', [Date.now() - 30 * 86400000]).catch(() => {}), 3600000);

initDb()
  .then(() => server.listen(process.env.PORT || 3000, () => console.log('Çalışıyor: http://localhost:' + (process.env.PORT || 3000))))
  .catch(e => { console.error('Veritabanı hatası:', e); process.exit(1); });

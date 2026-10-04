/**
 * AgentForge v5 – Backend mit Login, Refresh-Token, Rate-Limit, Passwort-Reset,
 *                 Share-Links und LLM-Proxy. Frontend wird statisch ausgeliefert.
 *
 * Endpunkte:
 *   POST   /api/auth/register              – Konto anlegen (Rate-Limit)
 *   POST   /api/auth/login                 – Login (Rate-Limit, gibt Access + Refresh)
 *   POST   /api/auth/refresh               – aus Refresh einen neuen Access holen
 *   POST   /api/auth/logout                – Refresh-Token widerrufen
 *   POST   /api/auth/forgot-password       – mailt/schickt Reset-Token (Rate-Limit)
 *   POST   /api/auth/reset-password        – neues Passwort mit Reset-Token
 *   GET    /api/auth/me                    – aktueller User (Access-Token)
 *   GET    /api/agents                     – eigene Cloud-Agenten
 *   POST   /api/agents                     – anlegen
 *   PUT    /api/agents/:id                 – aktualisieren
 *   DELETE /api/agents/:id                 – löschen
 *   POST   /api/agents/:id/share           – Share-Token erzeugen
 *   GET    /api/share/:token               – öffentliche Read-only-Sicht
 *   GET    /v1/chat/completions            – kompatibler LLM-Proxy (wie v4)
 *   GET    /health                         – Service-Check (auch Share-Counter)
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const PORT = parseInt(process.env.PORT || '8787', 10);
const DATA_DIR = process.env.DATA_DIR || '.';
const DB_PATH = path.join(DATA_DIR, 'data.db');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const REFRESH_SECRET = JWT_SECRET + ':refresh';
const RESET_SECRET = JWT_SECRET + ':reset';
const PUBLICC_BASE = (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const TTL = {
  access: parseInt(process.env.ACCESS_TOKEN_TTL || '900', 10),
  refresh: parseInt(process.env.REFRESH_TOKEN_TTL || '2592000', 10),
  reset: parseInt(process.env.RESET_TOKEN_TTL || '600', 10),
  share: parseInt(process.env.SHARE_LINK_TTL || '604800', 10),
};
const LLM_PROVIDER = (process.env.PROVIDER || 'openai').toLowerCase();
const KEYS = {
  openai: process.env.OPENAI_API_KEY || '',
  anthropic: process.env.ANTHROPIC_API_KEY || '',
  gemini: process.env.GEMINI_API_KEY || '',
};
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const SMTP_HOST = process.env.SMTP_HOST || '';
const LIMITS = {
  auth: parseInt(process.env.RATE_LIMIT_AUTH || '10', 10),
  api: parseInt(process.env.RATE_LIMIT_API || '120', 10),
};

/* ---------------- DB ---------------- */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS share_links (
    token TEXT PRIMARY KEY,
    agent_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);
db.exec('CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id);');
db.exec('CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);');
db.exec('CREATE INDEX IF NOT EXISTS idx_share_agent ON share_links(agent_id);');

const stmts = {
  createUser:        db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)'),
  findUserByEmail:   db.prepare('SELECT * FROM users WHERE email = ?'),
  findUserById:      db.prepare('SELECT id, email, created_at FROM users WHERE id = ?'),
  setPasswordHash:   db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
  listAgents:        db.prepare('SELECT id, name, config, created_at, updated_at FROM agents WHERE user_id = ? ORDER BY datetime(updated_at) DESC'),
  getAgent:          db.prepare('SELECT * FROM agents WHERE id = ? AND user_id = ?'),
  insertAgent:       db.prepare('INSERT INTO agents (user_id, name, config) VALUES (?, ?, ?)'),
  updateAgent:       db.prepare('UPDATE agents SET name = ?, config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?'),
  deleteAgent:       db.prepare('DELETE FROM agents WHERE id = ? AND user_id = ?'),
  insertRefresh:     db.prepare('INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)'),
  findRefresh:       db.prepare('SELECT * FROM refresh_tokens WHERE jti = ? AND revoked = 0'),
  revokeRefresh:     db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?'),
  purgeExpired:      db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?'),
  insertShare:       db.prepare('INSERT INTO share_links (token, agent_id, user_id, expires_at) VALUES (?, ?, ?, ?)'),
  findShare:         db.prepare('SELECT s.token, s.expires_at, a.config FROM share_links s JOIN agents a ON s.agent_id = a.id WHERE s.token = ? AND s.user_id = a.user_id'),
};

let mailTransporter = null;
if (SMTP_HOST) {
  mailTransporter = nodemailer.createTransport({
    host: SMTP_HOST, port: parseInt(process.env.SMTP_PORT || '587', 10), secure: false,
    auth: SMTP_USER || SMTP_PASS ? { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' } : undefined,
  });
}

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: ALLOWED_ORIGIN, exposedHeaders: ['Retry-After'] }));
app.use(express.json({ limit: '2mb' }));

/* ---------------- HELPERS ---------------- */
function baseUrl(req) { return PUBLICC_BASE || req.protocol + '://' + req.get('host'); }
function safeAgentPayload(p) { const c = { ...p }; delete c.id; delete c._created_at; delete c._updated_at; delete c._id; return c; }
function validateEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }
function asyncLimiter(opts) {
  // build limiter that knows about both ip and optional user uid
  return rateLimit({
    windowMs: 60_000, max: opts.max,
    standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => (req.user?.uid ? 'u:' + req.user.uid : 'ip:' + (req.ip || req.connection?.remoteAddress || 'unk')),
    message: { error: 'Rate-Limit erreicht – bitte kurz warten.' },
  });
}
function sendResetMail(to, link) {
  const mail = { from: process.env.SMTP_FROM || 'no-reply@agentforge.local', to, subject: 'AgentForge: Passwort zurücksetzen', text: `Hallo,\n\nzum Zurücksetzen deines Passworts öffne folgenden Link (gültig 10 min):\n\n${link}\n\nFalls die Anfrage nicht von dir kam, ignoriere diese Mail.\n` };
  if (mailTransporter) return mailTransporter.sendMail(mail).then(() => ({ sent: true })).catch(e => ({ sent: false, err: e.message }));
  console.log(`[reset-mail PREVIEW] to=${to} link=${link}`);
  return Promise.resolve({ sent: 'preview', printed: true });
}

/* ---------------- AUTH TOKENS ---------------- */
function signAccess(user) { return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: TTL.access }); }
function signRefresh(user) {
  const jti = crypto.randomBytes(20).toString('hex');
  const token = jwt.sign({ uid: user.id, jti }, REFRESH_SECRET, { expiresIn: TTL.refresh });
  const exp = Math.floor(Date.now() / 1000) + TTL.refresh;
  stmts.insertRefresh.run(jti, user.id, exp);
  return { token, jti };
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!tok) return res.status(401).json({ error: 'Kein Token – bitte (re-)login.' });
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Access-Token ungültig oder abgelaufen – bitte erneuern.' }); }
}
function authOptional(req, _res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (tok) { try { req.user = jwt.verify(tok, JWT_SECRET); } catch {} }
  next();
}

const limitAuth = asyncLimiter({ max: LIMITS.auth });
const limitApi  = asyncLimiter({ max: LIMITS.api });

app.use('/api/', limitApi);

/* ---------------- AUTH ROUTES ---------------- */
app.post('/api/auth/register', limitAuth, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich.' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Passwort muss mindestens 6 Zeichen lang sein.' });
  const clean = String(email).trim().toLowerCase();
  if (!validateEmail(clean)) return res.status(400).json({ error: 'Ungültige E-Mail-Adresse.' });
  if (stmts.findUserByEmail.get(clean)) return res.status(409).json({ error: 'E-Mail ist bereits registriert.' });
  const hash = bcrypt.hashSync(password, 10);
  const info = stmts.createUser.run(clean, hash);
  const user = { id: info.lastInsertRowid, email: clean };
  const access = signAccess(user);
  const { token: refresh } = signRefresh(user);
  res.json({ access, refresh, user });
});

app.post('/api/auth/login', limitAuth, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'E-Mail und Passwort erforderlich.' });
  const clean = String(email).trim().toLowerCase();
  const row = stmts.findUserByEmail.get(clean);
  if (!row || !bcrypt.compareSync(password, row.password_hash))
    return res.status(401).json({ error: 'Ungültige Zugangsdaten.' });
  const user = { id: row.id, email: row.email, created_at: row.created_at };
  const access = signAccess(user);
  const { token: refresh } = signRefresh(user);
  res.json({ access, refresh, user });
});

app.post('/api/auth/refresh', limitAuth, (req, res) => {
  const { refresh } = req.body || {};
  if (!refresh) return res.status(400).json({ error: 'Refresh-Token benötigt.' });
  let payload;
  try { payload = jwt.verify(refresh, REFRESH_SECRET); }
  catch { return res.status(401).json({ error: 'Refresh-Token ungültig oder abgelaufen.' }); }
  const row = stmts.findRefresh.get(payload.jti);
  if (!row) return res.status(401).json({ error: 'Refresh-Token wurde widerrufen oder kennt der Server nicht.' });
  if (row.expires_at < Math.floor(Date.now() / 1000))
    return res.status(401).json({ error: 'Refresh-Token abgelaufen – bitte neu einloggen.' });
  const user = { id: row.user_id, email: stmts.findUserById.get(row.user_id)?.email || '' };
  res.json({ access: signAccess(user), user });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
  const { refresh } = req.body || {};
  if (!refresh) return res.status(400).json({ error: 'Refresh-Token benötigt.' });
  try {
    const p = jwt.verify(refresh, REFRESH_SECRET);
    stmts.revokeRefresh.run(p.jti);
    res.json({ ok: true });
  } catch { res.status(400).json({ ok: true, note: 'Refresh-Token bereits ungültig, Access-Tokens laufen ohnehin ab.' }); }
});

/* Passwort-Reset: Schritt 1 – Mail/linken.
   Im PREVIEW-Modus (ohne SMTP_HOST) wird das Token direkt zurückgegeben,
   damit die Funktion ohne Mail-Setup getestet werden kann. */
app.post('/api/auth/forgot-password', limitAuth, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'E-Mail benötigt.' });
  const clean = String(email).trim().toLowerCase();
  const u = stmts.findUserByEmail.get(clean);
  // Antwort ist IMMER 200, auch wenn der User nicht existiert (keine User-Enumeration)
  const reset = jwt.sign({ uid: u?.id || 0, sub: clean }, RESET_SECRET, { expiresIn: TTL.reset });
  const link = baseUrl(req) + '/reset?token=' + reset;
  if (u && SMTP_HOST) {
    await sendResetMail(clean, link);
    return res.json({ ok: true, sent: 'mail' });
  }
  if (u) {
    console.log(`[reset-mail PREVIEW] to=${clean} link=${link}`);
    return res.json({ ok: true, sent: 'preview', reset_link: link, reset_token: reset });
  }
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', limitAuth, (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Token und neues Passwort erforderlich.' });
  if (typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'Passwort muss mindestens 6 Zeichen lang sein.' });
  let payload;
  try { payload = jwt.verify(token, RESET_SECRET); }
  catch { return res.status(401).json({ error: 'Reset-Token ungültig oder abgelaufen.' }); }
  if (!payload.uid) return res.status(400).json({ error: 'Reset-Link ist für einen unbekannten User.' });
  const hash = bcrypt.hashSync(password, 10);
  stmts.setPasswordHash.run(hash, payload.uid);
  // Sicherheits: alle Refresh-Tokens des Users entwerten
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(payload.uid);
  res.json({ ok: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const u = stmts.findUserById.get(req.user.uid);
  if (!u) return res.status(404).json({ error: 'User nicht gefunden.' });
  res.json({ user: u });
});

/* ---------------- AGENT CRUD ---------------- */
app.get('/api/agents', authMiddleware, (req, res) => {
  res.json(stmts.listAgents.all(req.user.uid).map(r => ({ ...JSON.parse(r.config), id: r.id })));
});

app.post('/api/agents', authMiddleware, (req, res) => {
  const cfg = req.body || {};
  if (!cfg.name) return res.status(400).json({ error: 'Agent benötigt einen Namen.' });
  const info = stmts.insertAgent.run(req.user.uid, String(cfg.name), JSON.stringify(safeAgentPayload(cfg)));
  const row = stmts.getAgent.get(info.lastInsertRowid, req.user.uid);
  res.json({ ...JSON.parse(row.config), id: row.id });
});

app.put('/api/agents/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const cfg = req.body || {};
  if (!cfg.name) return res.status(400).json({ error: 'Agent benötigt einen Namen.' });
  const r = stmts.updateAgent.run(String(cfg.name), JSON.stringify(safeAgentPayload(cfg)), id, req.user.uid);
  if (r.changes === 0) return res.status(404).json({ error: 'Agent nicht gefunden oder nicht erlaubt.' });
  const row = stmts.getAgent.get(id, req.user.uid);
  res.json({ ...JSON.parse(row.config), id: row.id });
});

app.delete('/api/agents/:id', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const r = stmts.deleteAgent.run(id, req.user.uid);
  if (r.changes === 0) return res.status(404).json({ error: 'Agent nicht gefunden oder nicht erlaubt.' });
  res.json({ ok: true });
});

/* ---------------- SHARE LINKS ---------------- */
app.post('/api/agents/:id/share', authMiddleware, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const own = stmts.getAgent.get(id, req.user.uid);
  if (!own) return res.status(404).json({ error: 'Agent nicht gefunden oder nicht erlaubt.' });
  const token = crypto.randomBytes(24).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + (parseInt(req.body?.expiresIn, 10) || TTL.share);
  stmts.insertShare.run(token, id, req.user.uid, exp);
  res.json({ token, url: baseUrl(req) + '/share/' + token, expires_at: exp });
});

app.get('/api/share/:token', (req, res) => {
  const row = stmts.findShare.get(req.params.token);
  if (!row) return res.status(404).json({ error: 'Share-Link unbekannt.' });
  if (row.expires_at < Math.floor(Date.now() / 1000))
    return res.status(410).json({ error: 'Share-Link abgelaufen.' });
  res.json({ config: JSON.parse(row.config), read_only: true });
});

/* ---------------- LLM PROXY ---------------- */
app.get('/health', (_req, res) => {
  const refreshCount = db.prepare('SELECT COUNT(*) AS c FROM refresh_tokens WHERE revoked = 0 AND expires_at > ?').get(Math.floor(Date.now() / 1000)).c;
  const shareCount = db.prepare('SELECT COUNT(*) AS c FROM share_links WHERE expires_at > ?').get(Math.floor(Date.now() / 1000)).c;
  res.json({ ok: true, provider: LLM_PROVIDER, llmConfigured: !!KEYS[LLM_PROVIDER], db: DB_PATH, refreshsActive: refreshCount, sharesActive: shareCount, mailMode: SMTP_HOST ? 'smtp' : 'preview' });
});

async function forwardOpenAI(body) {
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + KEYS.openai },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json() };
}
async function forwardAnthropic(body) {
  const msgs = body.messages || [];
  const system = msgs.filter(m => m.role === 'system').map(m => m.content).join('\n') || undefined;
  const messages = msgs.filter(m => m.role !== 'system').map(m => ({ role: m.role, content: m.content }));
  const a = { model: body.model, messages, max_tokens: body.max_tokens || 2048, temperature: body.temperature };
  if (system) a.system = system;
  if (body.tools) a.tools = body.tools.map(t => ({ name: t.function.name, description: t.function.description, input_schema: t.function.parameters }));
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': KEYS.anthropic, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify(a),
  });
  const j = await r.json();
  if (!r.ok) return { status: r.status, json: j };
  const text = (j.content || []).filter(x => x.type === 'text').map(x => x.text).join('');
  const toolCalls = (j.content || []).filter(x => x.type === 'tool_use').map((b, i) => ({
    id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input || {}) },
  }));
  return { status: 200, json: { id: j.id, object: 'chat.completion', model: j.model,
    choices: [{ index: 0, finish_reason: j.stop_reason === 'tool_use' ? 'tool_calls' : 'stop',
      message: { role: 'assistant', content: text || null, ...(toolCalls.length ? { tool_calls: toolCalls } : {}) } }],
    usage: { prompt_tokens: j.usage?.input_tokens || 0, completion_tokens: j.usage?.output_tokens || 0, total_tokens: (j.usage?.input_tokens || 0) + (j.usage?.output_tokens || 0) } } };
}
async function forwardGemini(body) {
  const msgs = body.messages || [];
  const system = msgs.filter(m => m.role === 'system').map(m => m.content).join('\n');
  const contents = msgs.filter(m => m.role !== 'system').map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }));
  const gbody = { contents, generationConfig: { temperature: body.temperature, maxOutputTokens: body.max_tokens || 2048 } };
  if (system) gbody.systemInstruction = { parts: [{ text: system }] };
  if (body.tools) gbody.tools = [{ function_declarations: body.tools.map(t => ({ name: t.function.name, description: t.function.description, parameters: t.function.parameters })) }];
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${body.model}:generateContent?key=${KEYS.gemini}`;
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(gbody) });
  const j = await r.json();
  if (!r.ok) return { status: r.status, json: j };
  const parts = j.candidates?.[0]?.content?.parts || [];
  const text = parts.filter(p => p.text).map(p => p.text).join('');
  const toolCalls = parts.filter(p => p.functionCall).map((p, i) => ({ id: 'call_' + i, type: 'function', function: { name: p.functionCall.name, arguments: JSON.stringify(p.functionCall.args || {}) } }));
  return { status: 200, json: { id: 'gemini-' + Date.now(), object: 'chat.completion', model: body.model,
    choices: [{ index: 0, finish_reason: toolCalls.length ? 'tool_calls' : 'stop',
      message: { role: 'assistant', content: text || null, ...(toolCalls.length ? { tool_calls: toolCalls } : {}) } }],
    usage: { prompt_tokens: j.usageMetadata?.promptTokenCount || 0, completion_tokens: j.usageMetadata?.candidatesTokenCount || 0, total_tokens: j.usageMetadata?.totalTokenCount || 0 } } };
}

app.post('/v1/chat/completions', authOptional, async (req, res) => {
  if (!KEYS[LLM_PROVIDER]) return res.status(500).json({ error: { message: `Kein API-Key für Provider "${LLM_PROVIDER}" (ENV setzen).` } });
  const body = req.body || {}; body.stream = false;
  let out;
  if (LLM_PROVIDER === 'anthropic') out = await forwardAnthropic(body);
  else if (LLM_PROVIDER === 'gemini') out = await forwardGemini(body);
  else out = await forwardOpenAI(body);
  res.status(out.status).json(out.json);
});

/* periodically purge expired refresh tokens (every hour) */
setInterval(() => stmts.purgeExpired.run(Math.floor(Date.now() / 1000)), 3_600_000).unref();

/* ---------------- FRONTEND STATIC ---------------- */
app.use(express.static(__dirname, { extensions: ['html'] }));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
  console.log(`✅ AgentForge v5 → http://localhost:${PORT}`);
  console.log(`   Version       : 0.5  |  Provider=${LLM_PROVIDER}  |  Mail=${SMTP_HOST ? 'SMTP' : 'PREVIEW'}`);
  console.log(`   DB            : ${path.resolve(DB_PATH)}`);
  console.log(`   JWT-Secret    : ${process.env.JWT_SECRET ? 'aus ENV' : 'AUTO (jeden Restart neu!)'}`);
  console.log(`   CORS          : ${ALLOWED_ORIGIN}`);
  console.log(`   Limits (min)  : auth=${LIMITS.auth}/min  api=${LIMITS.api}/min`);
  console.log(`   Token-TTLs    : access=${TTL.access}s refresh=${TTL.refresh}s reset=${TTL.reset}s share=${TTL.share}s`);
});

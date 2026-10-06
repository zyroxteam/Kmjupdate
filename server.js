/**
 * KMJ TIPS — backend API + static admin panel server.
 *
 * Public API (rate-limited):
 *   POST /api/keys/verify   {key, device_id, package, version_code}
 *   GET  /api/update        -> update JSON for the Android SDK
 *   GET  /api/health
 *
 * Admin API (JWT bearer auth):
 *   POST /api/admin/setup            first-run admin creation (disabled once an admin exists)
 *   POST /api/admin/login            {username, password} -> {token}
 *   POST /api/admin/change-password  {current_password, new_password}
 *   GET  /api/admin/stats
 *   GET  /api/admin/keys?status=&q=&limit=&offset=
 *   POST /api/admin/keys             {prefix, label, expiry_days, count, single_use}
 *   POST /api/admin/keys/:id/revoke
 *   DELETE /api/admin/keys/:id
 *   GET  /api/admin/keys/export      -> CSV download
 *   GET  /api/admin/update
 *   PUT  /api/admin/update           {version_name, version_code, title, changelog,
 *                                    download_url, website_url, force_update}
 *
 * Secrets come ONLY from environment variables (see .env.example).
 * Nothing secret is ever sent to the panel or compiled into the DEX.
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const PORT = parseInt(process.env.PORT || '3000', 10);
const JWT_SECRET = process.env.JWT_SECRET || '';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '12h';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET env var is required (min 32 chars). See .env.example');
  process.exit(1);
}

const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '64kb' }));
// Serve the admin panel (static files in ./public)
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// ---------------- rate limiting ----------------
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true });
const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120, standardHeaders: true });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 600, standardHeaders: true });
app.use('/api/', apiLimiter);

// ---------------- helpers ----------------
const ok = (res, data) => res.json(Object.assign({ ok: true }, data));
const fail = (res, code, message) => res.status(code).json({ ok: false, error: message });

function requireAdmin(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return fail(res, 401, 'Missing token');
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    next();
  } catch (e) {
    return fail(res, 401, 'Invalid or expired token');
  }
}

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
function randomSegment(len) {
  const buf = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[buf[i] % ALPHABET.length];
  return s;
}
function generateKey(prefix) {
  const p = (prefix || 'KMJ').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'KMJ';
  return `${p}-${randomSegment(4)}-${randomSegment(4)}-${randomSegment(4)}-${randomSegment(4)}`;
}
function isHttpUrl(u) {
  return typeof u === 'string' && /^(https?:\/\/)[^\s/$.?#].[^\s]*$/i.test(u.trim());
}
function dayKey(ts) {
  const d = new Date(ts);
  return d.toISOString().slice(0, 10);
}

// ---------------- public: key verification ----------------
app.post('/api/keys/verify', verifyLimiter, (req, res) => {
  try {
    const { key, device_id, package: pkg, version_code } = req.body || {};
    if (typeof key !== 'string' || key.trim().length < 8 || key.trim().length > 64) {
      return res.json({ valid: false, status: 'invalid', message: 'Invalid key format' });
    }
    const clean = key.trim().toUpperCase();
    const deviceId = typeof device_id === 'string' ? device_id.slice(0, 128) : '';

    const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(clean);
    if (!row) {
      return res.json({ valid: false, status: 'invalid', message: 'Key not found' });
    }
    const now = Date.now();

    // Revoked always loses.
    if (row.status === 'revoked') {
      return res.json({ valid: false, status: 'revoked', message: 'This key has been revoked' });
    }
    // Expiry is enforced server-side on every check.
    if (row.status === 'expired' || (row.expires_at && now > row.expires_at)) {
      if (row.status !== 'expired') {
        db.prepare("UPDATE keys SET status='expired' WHERE id=?").run(row.id);
      }
      return res.json({ valid: false, status: 'expired', message: 'This key has expired' });
    }
    // Single-use keys bind to the first device that verifies them.
    if (row.single_use && row.device_id && deviceId && row.device_id !== deviceId) {
      db.prepare("UPDATE keys SET status='used' WHERE id=?").run(row.id);
      return res.json({ valid: false, status: 'used', message: 'This key is already used on another device' });
    }

    // Success — record usage.
    db.prepare(`UPDATE keys SET use_count = use_count + 1, used_at = ?,
                device_id = CASE WHEN device_id = '' THEN ? ELSE device_id END
                WHERE id = ?`).run(now, deviceId, row.id);
    db.prepare('INSERT INTO key_events (key_id, event, device_id, created_at) VALUES (?, ?, ?, ?)')
      .run(row.id, 'verified', deviceId, now);

    const expiresOut = row.expires_at || null;
    return res.json({
      valid: true,
      status: row.single_use ? 'used' : 'active',
      message: 'Key verified successfully',
      expires_at: expiresOut,
      label: row.label || ''
    });
  } catch (e) {
    console.error('verify error:', e.message);
    return fail(res, 500, 'Verification failed');
  }
});

// ---------------- public: update info ----------------
app.get('/api/update', (req, res) => {
  try {
    const u = db.prepare('SELECT * FROM app_update WHERE id = 1').get();
    res.json({
      latest_version: u.version_name,
      version_code: u.version_code,
      update_available: u.version_code > 0 && u.download_url.length > 0,
      force_update: u.force_update === 1,
      title: u.title,
      changelog: u.changelog,
      download_url: u.download_url,
      website_url: u.website_url || undefined
    });
  } catch (e) {
    return fail(res, 500, 'Could not load update info');
  }
});

app.get('/api/health', (req, res) => ok(res, { service: 'kmj-tips', time: Date.now() }));

// ---------------- admin: setup & login ----------------
app.post('/api/admin/setup', loginLimiter, (req, res) => {
  try {
    const count = db.prepare('SELECT COUNT(*) AS c FROM admins').get().c;
    if (count > 0) return fail(res, 403, 'Setup is disabled — an admin already exists');
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || !/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
      return fail(res, 400, 'Username must be 3-32 chars (letters, numbers, _ . -)');
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      return fail(res, 400, 'Password must be 8-128 characters');
    }
    const hash = bcrypt.hashSync(password, 12);
    db.prepare('INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)')
      .run(username, hash, Date.now());
    return ok(res, { message: 'Admin created. Please log in.' });
  } catch (e) {
    return fail(res, 500, 'Setup failed');
  }
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return fail(res, 400, 'Username and password required');
    }
    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    // Constant-time-ish: always run a compare to avoid user enumeration timing.
    const hash = admin ? admin.password_hash : bcrypt.hashSync('dummy', 4);
    const valid = bcrypt.compareSync(password, hash);
    if (!admin || !valid) return fail(res, 401, 'Invalid username or password');
    const token = jwt.sign({ sub: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    return ok(res, { token, username: admin.username, expires_in: JWT_EXPIRES });
  } catch (e) {
    return fail(res, 500, 'Login failed');
  }
});

app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  try {
    const { current_password, new_password } = req.body || {};
    if (typeof new_password !== 'string' || new_password.length < 8 || new_password.length > 128) {
      return fail(res, 400, 'New password must be 8-128 characters');
    }
    const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.admin.sub);
    if (!admin || !bcrypt.compareSync(current_password || '', admin.password_hash)) {
      return fail(res, 401, 'Current password is incorrect');
    }
    db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?')
      .run(bcrypt.hashSync(new_password, 12), admin.id);
    return ok(res, { message: 'Password changed' });
  } catch (e) {
    return fail(res, 500, 'Could not change password');
  }
});

// ---------------- admin: dashboard stats ----------------
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const counts = {};
    for (const s of ['active', 'used', 'expired', 'revoked']) {
      counts[s] = db.prepare('SELECT COUNT(*) AS c FROM keys WHERE status = ?').get(s).c;
    }
    counts.total = db.prepare('SELECT COUNT(*) AS c FROM keys').get().c;
    const upd = db.prepare('SELECT version_name, version_code, force_update FROM app_update WHERE id = 1').get();

    // 14-day activity series.
    const days = [];
    const created = [];
    const verified = [];
    const nowDay = new Date(); nowDay.setHours(0, 0, 0, 0);
    for (let i = 13; i >= 0; i--) {
      const start = nowDay.getTime() - i * 86400000;
      const end = start + 86400000;
      days.push(new Date(start).toISOString().slice(5, 10));
      created.push(db.prepare("SELECT COUNT(*) AS c FROM key_events WHERE event='created' AND created_at >= ? AND created_at < ?").get(start, end).c);
      verified.push(db.prepare("SELECT COUNT(*) AS c FROM key_events WHERE event='verified' AND created_at >= ? AND created_at < ?").get(start, end).c);
    }
    const recent = db.prepare(`SELECT k.key, k.label, k.status, e.event, e.created_at, e.device_id
      FROM key_events e JOIN keys k ON k.id = e.key_id
      ORDER BY e.created_at DESC LIMIT 10`).all();

    return ok(res, {
      keys: counts,
      current_version: { version_name: upd.version_name, version_code: upd.version_code, force_update: upd.force_update === 1 },
      chart: { days, created, verified },
      recent_activity: recent
    });
  } catch (e) {
    console.error('stats error:', e.message);
    return fail(res, 500, 'Could not load stats');
  }
});

// ---------------- admin: keys ----------------
app.get('/api/admin/keys', requireAdmin, (req, res) => {
  try {
    const status = req.query.status;
    const q = (req.query.q || '').trim();
    const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset || '0', 10) || 0, 0);

    let where = '1=1';
    const params = [];
    if (['active', 'used', 'expired', 'revoked'].includes(status)) {
      where += ' AND status = ?'; params.push(status);
    }
    if (q) { where += ' AND (key LIKE ? OR label LIKE ?)'; params.push(`%${q}%`, `%${q}%`); }

    const total = db.prepare(`SELECT COUNT(*) AS c FROM keys WHERE ${where}`).get(...params).c;
    const rows = db.prepare(`SELECT id, key, prefix, label, status, single_use, created_at,
      expires_at, used_at, device_id, use_count FROM keys
      WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
    return ok(res, { total, limit, offset, keys: rows });
  } catch (e) {
    return fail(res, 500, 'Could not list keys');
  }
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
  try {
    let { prefix, label, expiry_days, count, single_use } = req.body || {};
    prefix = typeof prefix === 'string' ? prefix.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) : '';
    if (!prefix) prefix = 'KMJ';
    label = typeof label === 'string' ? label.trim().slice(0, 64) : '';
    count = parseInt(count, 10);
    if (!Number.isFinite(count) || count < 1 || count > 100) count = 1;
    let expiresAt = null;
    if (expiry_days === 1 || expiry_days === 7 || expiry_days === 30) {
      expiresAt = Date.now() + expiry_days * 86400000;
    } else if (expiry_days !== null && expiry_days !== undefined && expiry_days !== 'lifetime') {
      return fail(res, 400, 'expiry_days must be 1, 7, 30 or null (lifetime)');
    }
    const singleUse = single_use === true || single_use === 1 ? 1 : 0;

    const insKey = db.prepare(`INSERT INTO keys
      (key, prefix, label, status, single_use, created_at, expires_at) VALUES (?, ?, ?, 'active', ?, ?, ?)`);
    const insEvt = db.prepare('INSERT INTO key_events (key_id, event, created_at) VALUES (?, ?, ?)');
    const made = [];
    const now = Date.now();
    for (let i = 0; i < count; i++) {
      let k = generateKey(prefix);
      // Uniqueness: retry on the (astronomically unlikely) collision.
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const r = insKey.run(k, prefix, label, singleUse, now, expiresAt);
          insEvt.run(r.lastInsertRowid, 'created', now);
          made.push({ id: r.lastInsertRowid, key: k });
          break;
        } catch (e) {
          k = generateKey(prefix);
          if (attempt === 4) throw e;
        }
      }
    }
    return ok(res, { generated: made.length, keys: made });
  } catch (e) {
    console.error('keygen error:', e.message);
    return fail(res, 500, 'Could not generate keys');
  }
});

app.post('/api/admin/keys/:id/revoke', requireAdmin, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const row = db.prepare('SELECT id FROM keys WHERE id = ?').get(id);
    if (!row) return fail(res, 404, 'Key not found');
    db.prepare("UPDATE keys SET status = 'revoked' WHERE id = ?").run(id);
    db.prepare('INSERT INTO key_events (key_id, event, created_at) VALUES (?, ?, ?)')
      .run(id, 'revoked', Date.now());
    return ok(res, { message: 'Key revoked' });
  } catch (e) {
    return fail(res, 500, 'Could not revoke key');
  }
});

app.delete('/api/admin/keys/:id', requireAdmin, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const r = db.prepare('DELETE FROM keys WHERE id = ?').run(id);
    db.prepare('DELETE FROM key_events WHERE key_id = ?').run(id);
    if (r.changes === 0) return fail(res, 404, 'Key not found');
    return ok(res, { message: 'Key deleted' });
  } catch (e) {
    return fail(res, 500, 'Could not delete key');
  }
});

app.get('/api/admin/keys/export', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(`SELECT key, prefix, label, status, single_use, created_at,
      expires_at, use_count FROM keys ORDER BY created_at DESC`).all();
    const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    const lines = ['key,prefix,label,status,single_use,created_at,expires_at,use_count'];
    for (const r of rows) {
      lines.push([r.key, r.prefix, r.label, r.status, r.single_use,
        new Date(r.created_at).toISOString(),
        r.expires_at ? new Date(r.expires_at).toISOString() : 'lifetime',
        r.use_count].map(esc).join(','));
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="kmj-keys-export.csv"');
    res.send(lines.join('\n'));
  } catch (e) {
    return fail(res, 500, 'Export failed');
  }
});

// ---------------- admin: update management ----------------
app.get('/api/admin/update', requireAdmin, (req, res) => {
  try {
    const u = db.prepare('SELECT * FROM app_update WHERE id = 1').get();
    return ok(res, { update: u });
  } catch (e) {
    return fail(res, 500, 'Could not load update info');
  }
});

app.put('/api/admin/update', requireAdmin, (req, res) => {
  try {
    const { version_name, version_code, title, changelog, download_url, website_url, force_update } = req.body || {};
    if (typeof version_name !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(version_name.trim())) {
      return fail(res, 400, 'version_name is invalid (e.g. 1.2.0)');
    }
    const vc = parseInt(version_code, 10);
    if (!Number.isFinite(vc) || vc < 0 || vc > 2100000000) {
      return fail(res, 400, 'version_code must be a positive integer');
    }
    if (typeof download_url !== 'string' || !isHttpUrl(download_url)) {
      return fail(res, 400, 'download_url must be a valid http(s) URL');
    }
    if (website_url && website_url.trim() && !isHttpUrl(website_url)) {
      return fail(res, 400, 'website_url must be a valid http(s) URL or empty');
    }
    db.prepare(`UPDATE app_update SET version_name=?, version_code=?, title=?,
      changelog=?, download_url=?, website_url=?, force_update=?, updated_at=? WHERE id=1`)
      .run(version_name.trim(), vc,
        (title || 'New Update Available').toString().slice(0, 120),
        (changelog || '').toString().slice(0, 4000),
        download_url.trim(),
        (website_url || '').toString().trim(),
        force_update ? 1 : 0, Date.now());
    return ok(res, { message: 'Update info saved' });
  } catch (e) {
    return fail(res, 500, 'Could not save update info');
  }
});

// Fallback: let the panel handle unknown routes (but never shadow /api).
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return fail(res, 404, 'Not found');
  next();
});

app.listen(PORT, () => {
  console.log(`KMJ TIPS panel running on http://localhost:${PORT}`);
  const c = db.prepare('SELECT COUNT(*) AS c FROM admins').get().c;
  if (c === 0) console.log('No admin yet — run "npm run setup" to create one, then open /setup in the panel.');
});

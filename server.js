/* Angel One proxy for the Trade app — runs on Northflank (or anywhere with Node 20+).
   No npm packages needed. Endpoints used by index.html:
     GET  /            -> "ok" (no token; used to wake / health-check)
     GET  /state       -> saved app state          (x-app-token required)
     PUT  /state       -> save app state
     POST /quote       -> {tokens:[..]} -> live quotes
     GET  /search?q=   -> NSE symbol search
     GET  /candles?token=&interval=&days=
*/
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = +process.env.PORT || 3000;
const APP_TOKEN = process.env.APP_TOKEN || '';
const API_KEY = process.env.ANGEL_API_KEY || '';
const CLIENT_ID = process.env.ANGEL_CLIENT_ID || '';
const PIN = process.env.ANGEL_PIN || '';
const TOTP_SECRET = (process.env.ANGEL_TOTP_SECRET || '').replace(/\s+/g, '').toUpperCase();
const ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ANGEL = process.env.ANGEL_BASE || 'https://apiconnect.angelone.in';
const SCRIP_URL = process.env.SCRIP_URL || 'https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json';

try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const SCRIP_FILE = path.join(DATA_DIR, 'nse-eq.json');
const log = (...a) => console.log(new Date().toISOString(), ...a);

/* ---------- TOTP (RFC 6238) ---------- */
function b32(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of s.replace(/=+$/, '')) { const v = A.indexOf(c); if (v < 0) throw new Error('Bad TOTP secret'); bits += v.toString(2).padStart(5, '0'); }
  const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp() {
  const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', b32(TOTP_SECRET)).update(ctr).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1e6).padStart(6, '0');
}

/* ---------- Angel One session ---------- */
let jwt = '', loginP = null, lastLoginFail = 0, lastLoginErr = '';
const baseHeaders = () => ({
  'Content-Type': 'application/json', Accept: 'application/json', 'X-UserType': 'USER', 'X-SourceID': 'WEB',
  'X-ClientLocalIP': '127.0.0.1', 'X-ClientPublicIP': '127.0.0.1', 'X-MACAddress': '00:00:00:00:00:00', 'X-PrivateKey': API_KEY
});
async function login() {
  if (loginP) return loginP;
  if (Date.now() - lastLoginFail < 60000) throw httpErr(502, 'Angel login failed recently, waiting 60s before retry: ' + lastLoginErr);
  loginP = (async () => {
    try {
      if (!API_KEY || !CLIENT_ID || !PIN || !TOTP_SECRET) throw new Error('Missing ANGEL_* environment variables');
      const r = await fetch(ANGEL + '/rest/auth/angelbroking/user/v1/loginByPassword', {
        method: 'POST', headers: baseHeaders(), body: JSON.stringify({ clientcode: CLIENT_ID, password: PIN, totp: totp() })
      });
      const j = await r.json().catch(() => ({}));
      if (!j.status || !j.data || !j.data.jwtToken) throw new Error(j.message || ('HTTP ' + r.status));
      jwt = j.data.jwtToken; lastLoginFail = 0; log('Angel login OK');
    } catch (e) { lastLoginFail = Date.now(); lastLoginErr = e.message; jwt = ''; log('Angel login FAILED:', e.message); throw httpErr(502, 'Angel login failed: ' + e.message); }
    finally { loginP = null; }
  })();
  return loginP;
}
const httpErr = (code, msg) => Object.assign(new Error(msg), { code });
const isAuthFail = j => j && j.status === false && (/AG800[1-3]/.test(j.errorcode || '') || /token|session/i.test(j.message || ''));
async function angel(pathname, body, retry = true) {
  if (!jwt) await login();
  const r = await fetch(ANGEL + pathname, { method: 'POST', headers: { ...baseHeaders(), Authorization: 'Bearer ' + jwt }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if ((r.status === 401 || isAuthFail(j)) && retry) { log('Angel rejected the session (' + (j.message || r.status) + ') - logging in again'); jwt = ''; return angel(pathname, body, false); }
  if (r.status === 429 || /rate/i.test(j.message || '') && j.status === false) throw httpErr(429, j.message || 'Rate limited');
  if (j.status === false) throw httpErr(502, j.message || 'Angel error');
  return j;
}

/* ---------- NSE symbol list (streamed so it fits in small free containers) ---------- */
let SCRIPS = [], scripsReady = false;
function loadScripCache() {
  try { const st = fs.statSync(SCRIP_FILE); if (Date.now() - st.mtimeMs < 20 * 3600e3) { SCRIPS = JSON.parse(fs.readFileSync(SCRIP_FILE, 'utf8')); scripsReady = SCRIPS.length > 0; return true } } catch {}
  return false;
}
async function downloadScrips() {
  log('Downloading Angel scrip master…');
  const r = await fetch(SCRIP_URL); if (!r.ok) throw new Error('scrip master HTTP ' + r.status);
  const out = []; let buf = ''; const dec = new TextDecoder();
  const take = () => { let s; while ((s = buf.indexOf('{')) >= 0) { const e = buf.indexOf('}', s); if (e < 0) break;
      try { const o = JSON.parse(buf.slice(s, e + 1)); if (o.exch_seg === 'NSE' && /-EQ$/.test(o.symbol || '')) out.push({ token: String(o.token), symbol: o.symbol.replace(/-EQ$/, ''), name: o.name || '' }); } catch {}
      buf = buf.slice(e + 1); } };
  for await (const chunk of r.body) { buf += dec.decode(chunk, { stream: true }); take(); }
  buf += dec.decode(); take();
  if (out.length < 100) throw new Error('scrip master looked empty');
  SCRIPS = out; scripsReady = true; fs.writeFileSync(SCRIP_FILE, JSON.stringify(out)); log('NSE equities loaded:', out.length);
}
async function scripLoop() {
  for (;;) {
    try { if (!loadScripCache()) await downloadScrips(); } catch (e) { log('Scrip load failed:', e.message); await new Promise(r => setTimeout(r, 30000)); continue; }
    await new Promise(r => setTimeout(r, 6 * 3600e3)); // re-check every 6h (cache is valid 20h)
  }
}
function search(q) {
  q = q.toUpperCase().trim(); if (q.length < 1) return [];
  const sc = x => x.symbol === q ? 0 : x.symbol.startsWith(q) ? 1 : x.name === q ? 2 : x.name.startsWith(q) ? 3 : (x.symbol.includes(q) || x.name.includes(q)) ? 4 : 9;
  return SCRIPS.map(x => [sc(x), x]).filter(a => a[0] < 9).sort((a, b) => a[0] - b[0] || a[1].symbol.length - b[1].symbol.length).slice(0, 25).map(a => a[1]);
}

/* ---------- quotes: queued, de-duplicated and rate-limit friendly ---------- */
let qTail = Promise.resolve(); const qCache = new Map();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const enqueue = fn => { const r = qTail.then(fn, fn); qTail = r.then(() => sleep(150), () => sleep(150)); return r; };
function quote(tokens) {
  const key = tokens.join(','), c = qCache.get(key);
  if (c && Date.now() - c.t < 1500) return c.p;
  const p = enqueue(async () => {
    for (let a = 0; ; a++) {
      try { const j = await angel('/rest/secure/angelbroking/market/v1/quote/', { mode: 'FULL', exchangeTokens: { NSE: tokens } }); return (j.data && j.data.fetched) || []; }
      catch (e) { if (e.code === 429 && a < 2) { await sleep(1200); continue; } throw e; }
    }
  });
  qCache.set(key, { t: Date.now(), p }); p.catch(() => qCache.delete(key)); setTimeout(() => qCache.delete(key), 2000);
  return p;
}

/* ---------- candles ---------- */
const MAXD = { ONE_MINUTE: 30, THREE_MINUTE: 60, FIVE_MINUTE: 100, TEN_MINUTE: 100, FIFTEEN_MINUTE: 200, THIRTY_MINUTE: 200, ONE_HOUR: 400, ONE_DAY: 2000 };
const ist = ms => new Date(ms + 19800e3).toISOString().slice(0, 16).replace('T', ' ');
async function candles(token, interval, days) {
  if (!MAXD[interval]) throw httpErr(400, 'Bad interval');
  days = Math.max(1, Math.min(+days || 5, MAXD[interval]));
  const now = Date.now();
  const j = await angel('/rest/secure/angelbroking/historical/v1/getCandleData', {
    exchange: 'NSE', symboltoken: String(token), interval, fromdate: ist(now - days * 86400e3), todate: ist(now) });
  return (j.data || []).map(c => ({ time: Math.floor(Date.parse(c[0]) / 1000), open: c[1], high: c[2], low: c[3], close: c[4], volume: c[5] }));
}

/* ---------- HTTP server ---------- */
function send(res, code, body) {
  const s = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(code, { 'Content-Type': typeof body === 'string' ? 'text/plain' : 'application/json', 'Access-Control-Allow-Origin': ORIGIN,
    'Access-Control-Allow-Headers': res._rh || 'x-app-token, content-type', 'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
    'Access-Control-Max-Age': '86400', 'Vary': 'Origin, Access-Control-Request-Headers', 'Cache-Control': 'no-store' });
  res.end(s);
}
const readBody = req => new Promise((ok, no) => { let b = ''; req.on('data', c => { b += c; if (b.length > 3e6) { no(httpErr(413, 'Too large')); req.destroy() } }); req.on('end', () => ok(b)); req.on('error', no); });
const tokOk = h => { const a = Buffer.from(String(h || '')), b = Buffer.from(APP_TOKEN); return APP_TOKEN && a.length === b.length && crypto.timingSafeEqual(a, b) };

http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  res._rh = req.headers['access-control-request-headers'] || '';
  if (u.pathname !== '/' && u.pathname !== '/health') res.on('finish', () => log(req.method, u.pathname, res.statusCode, 'origin=' + (req.headers.origin || '-')));
  try {
    if (req.method === 'OPTIONS') return send(res, 204, '');
    if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/health')) return send(res, 200, 'ok');
    if (!tokOk(req.headers['x-app-token'])) return send(res, 401, { error: 'Bad or missing token' });

    if (u.pathname === '/state' && req.method === 'GET') { try { return send(res, 200, JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'))) } catch { return send(res, 200, {}) } }
    if (u.pathname === '/state' && req.method === 'PUT') { const b = JSON.parse(await readBody(req) || '{}'); fs.writeFileSync(STATE_FILE + '.tmp', JSON.stringify(b)); fs.renameSync(STATE_FILE + '.tmp', STATE_FILE); return send(res, 200, { ok: true }); }

    if (u.pathname === '/quote' && req.method === 'POST') {
      const { tokens } = JSON.parse(await readBody(req) || '{}');
      if (!Array.isArray(tokens) || !tokens.length) return send(res, 200, []);
      return send(res, 200, await quote(tokens.slice(0, 50).map(String)));
    }
    if (u.pathname === '/search' && req.method === 'GET') {
      if (!scripsReady) return send(res, 503, { error: 'Symbol list is still loading, try again in a minute' });
      return send(res, 200, search(u.searchParams.get('q') || ''));
    }
    if (u.pathname === '/candles' && req.method === 'GET')
      return send(res, 200, await candles(u.searchParams.get('token'), u.searchParams.get('interval'), u.searchParams.get('days')));
    return send(res, 404, { error: 'Not found' });
  } catch (e) { log(req.method, u.pathname, 'ERR', e.message); send(res, e.code || 500, { error: e.message }); }
}).listen(PORT, '0.0.0.0', () => {
  log('Proxy listening on', PORT);
  if (!APP_TOKEN) log('WARNING: APP_TOKEN is not set – every request will be refused');
  scripLoop();
  login().catch(() => {});   // log in at start so the first app request is fast
});

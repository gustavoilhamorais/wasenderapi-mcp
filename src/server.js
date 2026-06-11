'use strict';

// Minimal OAuth 2.1 (PKCE S256) facade proxy in front of a static-bearer MCP server.
// Fronts WASenderAPI's hosted MCP so Claude.ai custom connectors (which require
// OAuth 2.1 + PKCE and refuse static bearer tokens) can use it.
//
// Zero external deps: uses Node 24 built-ins (node:http, node:crypto, node:sqlite).
// node:sqlite is still experimental and prints a one-line ExperimentalWarning on start.

const http = require('node:http');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// ---------- Config ----------
const PORT = parseInt(process.env.PORT || '8080', 10);
// PUBLIC_BASE_URL is the externally-visible https origin (the Cloudflare tunnel URL),
// e.g. https://random-words.trycloudflare.com  (no trailing slash, no path).
let PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').replace(/\/+$/, '');
const CLOUDFLARED_METRICS_URL = process.env.CLOUDFLARED_METRICS_URL || '';
const UPSTREAM_MCP_URL = process.env.UPSTREAM_MCP_URL || 'https://wasenderapi.com/mcp';
const WASENDER_PAT = process.env.WASENDER_PAT || '';
const ADMIN_PASSPHRASE = process.env.ADMIN_PASSPHRASE || '';
const DB_PATH = process.env.DB_PATH || '/data/oauth.db';

// Token lifetimes (seconds)
const CODE_TTL = 10 * 60;          // 10 min
const ACCESS_TTL = 60 * 60;        // 1 hour
const REFRESH_TTL = 30 * 24 * 3600; // 30 days

// Limits
const MAX_BODY = 64 * 1024;        // 64 KB request-body cap
const MAX_CLIENTS = 100;           // hard cap on registered client rows
const CLIENT_TTL = 24 * 3600;      // prune token-less clients older than this
const RL_MAX_FAILS = 5;            // failed passphrase attempts before backoff
const RL_BLOCK_SEC = 5 * 60;       // backoff window once tripped

if (!WASENDER_PAT) console.warn('[warn] WASENDER_PAT is empty - upstream calls will fail.');
if (!ADMIN_PASSPHRASE) console.warn('[warn] ADMIN_PASSPHRASE is empty - consent gate is open!');
if (!PUBLIC_BASE_URL) console.warn('[warn] PUBLIC_BASE_URL is empty - discovery docs will be wrong until set.');

// ---------- DB ----------
const db = new DatabaseSync(DB_PATH);

// Tolerant migration: earlier versions stored raw access/refresh tokens in the
// `tokens` table. We now store only their SHA-256 hashes, so an old table layout
// is incompatible. Detect the legacy column and drop just that table (codes are
// short-lived and clients re-register), leaving the rest of the DB file intact.
// Consequence: tokens issued by a pre-hardening build stop working after upgrade.
{
  const tokenCols = db.prepare("PRAGMA table_info('tokens')").all();
  if (tokenCols.length && tokenCols.some((c) => c.name === 'access_token')) {
    console.warn('[migrate] dropping legacy plaintext-token table; existing tokens are invalidated.');
    db.exec('DROP TABLE tokens');
  }
}

db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    redirect_uris TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS tokens (
    access_token_hash TEXT PRIMARY KEY,
    refresh_token_hash TEXT,
    client_id TEXT NOT NULL,
    scope TEXT,
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_tokens_refresh ON tokens(refresh_token_hash);
`);

// ---------- helpers ----------
const now = () => Math.floor(Date.now() / 1000);
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');

// SHA-256 hex of a token, used as the at-rest identifier in SQLite.
const sha256hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// PKCE S256 challenge: base64url(SHA-256(verifier)).
function s256(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// Constant-time comparison of two secrets, length-blinded by hashing both to a
// fixed 32-byte digest before timingSafeEqual.
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

class PayloadTooLargeError extends Error {}

function json(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    ...corsHeaders(),
    ...extraHeaders,
  });
  res.end(body);
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Accept',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id, WWW-Authenticate',
  };
}

// Read the request body, enforcing MAX_BODY. On overflow we send a 413 and reject
// with PayloadTooLargeError so the handler stops; the socket is then destroyed.
function readBody(req, res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > MAX_BODY) {
        done = true;
        if (res && !res.headersSent) {
          res.writeHead(413, { 'Content-Type': 'application/json', Connection: 'close', ...corsHeaders() });
          // Flush the 413 to the client, then destroy the socket so we stop
          // reading (and stop buffering) any remaining oversized upload.
          res.end(JSON.stringify({ error: 'payload_too_large' }), () => req.destroy());
        } else {
          req.destroy();
        }
        reject(new PayloadTooLargeError());
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
    req.on('error', (e) => { if (!done) { done = true; reject(e); } });
  });
}

function parseForm(buf) {
  return Object.fromEntries(new URLSearchParams(buf.toString('utf8')));
}

// Best-effort client IP. Behind the Cloudflare tunnel the real client address is
// carried in CF-Connecting-IP / X-Forwarded-For; fall back to the socket peer.
function clientIp(req) {
  return req.headers['cf-connecting-ip']
    || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || (req.socket && req.socket.remoteAddress)
    || 'unknown';
}

// ---------- in-memory per-IP failed-auth backoff ----------
const authFails = new Map(); // ip -> { count, blockedUntil }

function authBlocked(ip) {
  const e = authFails.get(ip);
  if (!e) return false;
  if (e.blockedUntil > now()) return true;
  if (e.blockedUntil) authFails.delete(ip); // window elapsed; reset
  return false;
}
function noteAuthFail(ip) {
  const e = authFails.get(ip) || { count: 0, blockedUntil: 0 };
  e.count += 1;
  if (e.count >= RL_MAX_FAILS) e.blockedUntil = now() + RL_BLOCK_SEC;
  authFails.set(ip, e);
}
function noteAuthSuccess(ip) { authFails.delete(ip); }

// ---------- client lookup / validation ----------
function getClient(clientId) {
  if (!clientId) return null;
  return db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId) || null;
}
function clientAllowsRedirect(client, redirectUri) {
  if (!client || !redirectUri) return false;
  let uris;
  try { uris = JSON.parse(client.redirect_uris); } catch { return false; }
  return Array.isArray(uris) && uris.includes(redirectUri);
}

function pruneExpired() {
  const t = now();
  db.prepare('DELETE FROM codes WHERE expires_at < ?').run(t);
  db.prepare('DELETE FROM tokens WHERE refresh_expires_at < ?').run(t);
  // Drop client rows that never produced a token and have no live code, once
  // they are older than CLIENT_TTL. Keeps abandoned DCR registrations from
  // accumulating without touching clients that are actually in use.
  db.prepare(`DELETE FROM clients WHERE created_at < ?
    AND client_id NOT IN (SELECT client_id FROM tokens)
    AND client_id NOT IN (SELECT client_id FROM codes)`).run(t - CLIENT_TTL);
}

// Enforce MAX_CLIENTS at registration time. Returns true if still over the cap
// after pruning + evicting the oldest token-less rows (caller should then reject).
function tooManyClients() {
  pruneExpired();
  let { c } = db.prepare('SELECT COUNT(*) AS c FROM clients').get();
  if (c < MAX_CLIENTS) return false;
  db.prepare(`DELETE FROM clients WHERE client_id IN (
    SELECT client_id FROM clients
    WHERE client_id NOT IN (SELECT client_id FROM tokens)
    ORDER BY created_at ASC LIMIT ?)`).run(c - MAX_CLIENTS + 1);
  ({ c } = db.prepare('SELECT COUNT(*) AS c FROM clients').get());
  return c >= MAX_CLIENTS;
}

// ---------- discovery documents ----------
function protectedResourceMetadata() {
  return {
    resource: `${PUBLIC_BASE_URL}/mcp`,
    authorization_servers: [PUBLIC_BASE_URL],
    bearer_methods_supported: ['header'],
    scopes_supported: ['mcp'],
  };
}

function authServerMetadata() {
  return {
    issuer: PUBLIC_BASE_URL,
    authorization_endpoint: `${PUBLIC_BASE_URL}/authorize`,
    token_endpoint: `${PUBLIC_BASE_URL}/token`,
    registration_endpoint: `${PUBLIC_BASE_URL}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    // Public clients only: auth is PKCE, no client authentication method.
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['mcp'],
  };
}

const WWW_AUTH = () =>
  `Bearer error="invalid_token", error_description="Authentication required", ` +
  `resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp"`;

// ---------- consent page ----------
function consentPage(params, error) {
  const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'response_type']
    .map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(params[k] || '')}">`)
    .join('\n');
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize WASenderAPI MCP</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
  .card{background:#191c22;border:1px solid #2a2f3a;border-radius:14px;padding:32px;max-width:380px;width:90%}
  h1{font-size:18px;margin:0 0 4px}
  p{color:#9aa3b2;font-size:14px;margin:0 0 20px}
  input[type=password]{width:100%;box-sizing:border-box;padding:11px;border-radius:8px;border:1px solid #2a2f3a;background:#0f1115;color:#fff;font-size:15px}
  button{width:100%;margin-top:16px;padding:11px;border:0;border-radius:8px;background:#4f7cff;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
  .err{color:#ff6b6b;font-size:13px;margin-top:10px}
</style></head><body>
<form class="card" method="POST" action="/authorize">
  <h1>Authorize WASenderAPI MCP</h1>
  <p>Enter the admin passphrase to connect this WhatsApp MCP to Claude.</p>
  ${hidden}
  <input type="password" name="passphrase" placeholder="Admin passphrase" autofocus>
  ${error ? `<div class="err">${escapeHtml(error)}</div>` : ''}
  <button type="submit">Authorize</button>
</form></body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- token validation ----------
function validBearer(req) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const row = db.prepare('SELECT * FROM tokens WHERE access_token_hash = ?').get(sha256hex(m[1]));
  if (!row) return null;
  if (row.access_expires_at < now()) return null;
  return row;
}

// ---------- upstream proxy ----------
async function proxyToUpstream(req, res, bodyBuf) {
  const headers = {};
  // forward relevant MCP headers, drop hop-by-hop and inbound auth
  for (const [k, v] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (['host', 'authorization', 'connection', 'content-length', 'transfer-encoding'].includes(lk)) continue;
    headers[k] = v;
  }
  headers['authorization'] = `Bearer ${WASENDER_PAT}`;

  let upstream;
  try {
    upstream = await fetch(UPSTREAM_MCP_URL, {
      method: req.method,
      headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : bodyBuf,
    });
  } catch (e) {
    console.error('upstream fetch error', e);
    json(res, 502, { error: 'bad_gateway' });
    return;
  }

  const outHeaders = { ...corsHeaders() };
  upstream.headers.forEach((v, k) => {
    const lk = k.toLowerCase();
    if (['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(lk)) return;
    outHeaders[k] = v;
  });
  res.writeHead(upstream.status, outHeaders);

  if (!upstream.body) { res.end(); return; }
  // stream the response (supports SSE / streamable HTTP)
  const reader = upstream.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
  } catch (_) { /* client disconnected */ }
  res.end();
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, PUBLIC_BASE_URL || `http://localhost:${PORT}`);
  const path = url.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders());
    return res.end();
  }

  try {
    // --- discovery ---
    if (path === '/.well-known/oauth-protected-resource' || path === '/.well-known/oauth-protected-resource/mcp') {
      return json(res, 200, protectedResourceMetadata());
    }
    if (path === '/.well-known/oauth-authorization-server' || path === '/.well-known/openid-configuration') {
      return json(res, 200, authServerMetadata());
    }

    // --- dynamic client registration (RFC 7591) ---
    if (path === '/register' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req, res)).toString('utf8') || '{}');
      const redirectUris = Array.isArray(body.redirect_uris)
        ? body.redirect_uris.filter((u) => typeof u === 'string')
        : [];
      if (redirectUris.length === 0) {
        return json(res, 400, { error: 'invalid_redirect_uri', error_description: 'at least one redirect_uri is required' });
      }
      if (tooManyClients()) {
        return json(res, 429, { error: 'too_many_clients' });
      }
      const clientId = rand(16);
      db.prepare('INSERT INTO clients (client_id, redirect_uris, created_at) VALUES (?,?,?)')
        .run(clientId, JSON.stringify(redirectUris), now());
      // Public client: no client_secret is issued; auth is PKCE only.
      return json(res, 201, {
        client_id: clientId,
        client_id_issued_at: now(),
        redirect_uris: redirectUris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      });
    }

    // --- authorize (GET shows consent, POST verifies passphrase) ---
    if (path === '/authorize' && req.method === 'GET') {
      const p = Object.fromEntries(url.searchParams);
      const client = getClient(p.client_id);
      if (!client || !clientAllowsRedirect(client, p.redirect_uri)) {
        return json(res, 400, { error: 'invalid_request', error_description: 'unknown client_id or unregistered redirect_uri' });
      }
      if (p.code_challenge_method && p.code_challenge_method !== 'S256') {
        return json(res, 400, { error: 'invalid_request', error_description: 'only S256 PKCE supported' });
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders() });
      return res.end(consentPage(p));
    }
    if (path === '/authorize' && req.method === 'POST') {
      const ip = clientIp(req);
      const p = parseForm(await readBody(req, res));

      if (authBlocked(ip)) {
        res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders() });
        return res.end(consentPage(p, 'Too many attempts. Please wait a few minutes and try again.'));
      }

      const client = getClient(p.client_id);
      if (!client || !clientAllowsRedirect(client, p.redirect_uri)) {
        return json(res, 400, { error: 'invalid_request', error_description: 'unknown client_id or unregistered redirect_uri' });
      }
      if (!p.code_challenge) {
        return json(res, 400, { error: 'invalid_request', error_description: 'code_challenge required' });
      }
      if (p.code_challenge_method && p.code_challenge_method !== 'S256') {
        return json(res, 400, { error: 'invalid_request', error_description: 'only S256 PKCE supported' });
      }

      if (!ADMIN_PASSPHRASE || !safeEqual(p.passphrase || '', ADMIN_PASSPHRASE)) {
        noteAuthFail(ip);
        console.warn(`[auth] failed passphrase attempt ip=${ip}`);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders() });
        return res.end(consentPage(p, 'Incorrect passphrase.'));
      }
      noteAuthSuccess(ip);

      const code = rand(24);
      db.prepare('INSERT INTO codes (code, client_id, redirect_uri, code_challenge, scope, expires_at) VALUES (?,?,?,?,?,?)')
        .run(code, p.client_id, p.redirect_uri, p.code_challenge, p.scope || 'mcp', now() + CODE_TTL);
      const redir = new URL(p.redirect_uri);
      redir.searchParams.set('code', code);
      if (p.state) redir.searchParams.set('state', p.state);
      res.writeHead(302, { Location: redir.toString(), ...corsHeaders() });
      return res.end();
    }

    // --- token ---
    if (path === '/token' && req.method === 'POST') {
      pruneExpired();
      const p = parseForm(await readBody(req, res));

      if (p.grant_type === 'authorization_code') {
        const row = db.prepare('SELECT * FROM codes WHERE code = ?').get(p.code || '');
        if (!row || row.expires_at < now()) return json(res, 400, { error: 'invalid_grant' });
        db.prepare('DELETE FROM codes WHERE code = ?').run(p.code);
        if (!p.code_verifier || s256(p.code_verifier) !== row.code_challenge) {
          return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
        }
        if (!p.redirect_uri || p.redirect_uri !== row.redirect_uri) {
          return json(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
        }
        return issueTokens(res, row.client_id, row.scope);
      }

      if (p.grant_type === 'refresh_token') {
        const presented = sha256hex(p.refresh_token || '');
        const row = db.prepare('SELECT * FROM tokens WHERE refresh_token_hash = ?').get(presented);
        if (!row || row.refresh_expires_at < now()) return json(res, 400, { error: 'invalid_grant' });
        // Rotate: delete the old row so a replayed refresh token cannot be reused.
        db.prepare('DELETE FROM tokens WHERE access_token_hash = ?').run(row.access_token_hash);
        return issueTokens(res, row.client_id, row.scope);
      }

      return json(res, 400, { error: 'unsupported_grant_type' });
    }

    // --- MCP proxy ---
    if (path === '/mcp' || path.startsWith('/mcp/')) {
      const tok = validBearer(req);
      if (!tok) {
        return json(res, 401, { error: 'invalid_token', error_description: 'Authentication required' }, { 'WWW-Authenticate': WWW_AUTH() });
      }
      const bodyBuf = ['GET', 'HEAD'].includes(req.method) ? undefined : await readBody(req, res);
      return proxyToUpstream(req, res, bodyBuf);
    }

    if (path === '/' || path === '/health') {
      return json(res, 200, { ok: true, service: 'wasender-mcp-oauth-proxy', base: PUBLIC_BASE_URL });
    }

    return json(res, 404, { error: 'not_found' });
  } catch (e) {
    if (e instanceof PayloadTooLargeError) {
      if (!res.headersSent) json(res, 413, { error: 'payload_too_large' });
      return;
    }
    // Log full detail server-side; return an opaque message to the client.
    console.error('handler error', e);
    if (!res.headersSent) json(res, 500, { error: 'server_error' });
  }
});

// Issue a fresh access+refresh pair. Only the SHA-256 hashes are persisted;
// the raw tokens are returned once and never stored.
function issueTokens(res, clientId, scope) {
  const access = rand(32);
  const refresh = rand(32);
  const t = now();
  db.prepare(`INSERT INTO tokens (access_token_hash, refresh_token_hash, client_id, scope, access_expires_at, refresh_expires_at)
              VALUES (?,?,?,?,?,?)`)
    .run(sha256hex(access), sha256hex(refresh), clientId, scope || 'mcp', t + ACCESS_TTL, t + REFRESH_TTL);
  return json(res, 200, {
    access_token: access,
    token_type: 'Bearer',
    expires_in: ACCESS_TTL,
    refresh_token: refresh,
    scope: scope || 'mcp',
  });
}

// Auto-discover the current Cloudflare Quick Tunnel URL from cloudflared's
// metrics API. Quick Tunnel hostnames rotate on every cloudflared restart,
// so we self-configure on startup instead of relying on a static .env value.
async function discoverTunnelUrl() {
  if (!CLOUDFLARED_METRICS_URL) return;
  for (let i = 0; i < 30; i++) {
    try {
      const r = await fetch(CLOUDFLARED_METRICS_URL, { signal: AbortSignal.timeout(3000) });
      if (r.ok) {
        const data = await r.json();
        const url = (data.hostname || '').replace(/\/+$/, '');
        if (url) {
          const full = url.startsWith('http') ? url : 'https://' + url;
          if (full !== PUBLIC_BASE_URL) {
            console.log('[wasender-mcp-oauth-proxy] discovered tunnel URL: ' + full);
          }
          PUBLIC_BASE_URL = full;
          return;
        }
      }
    } catch (_) { /* not ready yet */ }
    await new Promise((res) => setTimeout(res, 2000));
  }
  console.warn('[warn] could not discover tunnel URL from ' + CLOUDFLARED_METRICS_URL + '; using PUBLIC_BASE_URL=' + (PUBLIC_BASE_URL || '(unset)'));
}

// Only auto-start when run directly (`node src/server.js`); when required by the
// test suite the server is started on an ephemeral port by the test itself.
if (require.main === module) {
  discoverTunnelUrl().finally(() => {
    server.listen(PORT, () => {
      console.log(`[wasender-mcp-oauth-proxy] listening on :${PORT}`);
      console.log(`[wasender-mcp-oauth-proxy] PUBLIC_BASE_URL=${PUBLIC_BASE_URL || '(unset)'}`);
      console.log(`[wasender-mcp-oauth-proxy] upstream=${UPSTREAM_MCP_URL}`);
    });
  });
}

module.exports = { server, db };

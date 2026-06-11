'use strict';

// Minimal OAuth 2.1 (PKCE S256) facade proxy in front of a static-bearer MCP server.
// Fronts WASenderAPI's hosted MCP so Claude.ai custom connectors (which require
// OAuth 2.1 + PKCE and refuse static bearer tokens) can use it.
//
// Zero external deps: uses Node 24 built-ins (node:http, node:crypto, node:sqlite).

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

if (!WASENDER_PAT) console.warn('[warn] WASENDER_PAT is empty - upstream calls will fail.');
if (!ADMIN_PASSPHRASE) console.warn('[warn] ADMIN_PASSPHRASE is empty - consent gate is open!');
if (!PUBLIC_BASE_URL) console.warn('[warn] PUBLIC_BASE_URL is empty - discovery docs will be wrong until set.');

// ---------- DB ----------
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT,
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
    access_token TEXT PRIMARY KEY,
    refresh_token TEXT,
    client_id TEXT NOT NULL,
    scope TEXT,
    access_expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_tokens_refresh ON tokens(refresh_token);
`);

// ---------- helpers ----------
const now = () => Math.floor(Date.now() / 1000);
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');

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

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseForm(buf) {
  return Object.fromEntries(new URLSearchParams(buf.toString('utf8')));
}

function s256(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function pruneExpired() {
  const t = now();
  db.prepare('DELETE FROM codes WHERE expires_at < ?').run(t);
  db.prepare('DELETE FROM tokens WHERE refresh_expires_at < ?').run(t);
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
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['mcp'],
    client_id_metadata_document_supported: true,
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
  const row = db.prepare('SELECT * FROM tokens WHERE access_token = ?').get(m[1]);
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
    json(res, 502, { error: 'bad_gateway', error_description: String(e) });
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
      const body = JSON.parse((await readBody(req)).toString('utf8') || '{}');
      const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
      const clientId = rand(16);
      const clientSecret = rand(24);
      db.prepare('INSERT INTO clients (client_id, client_secret, redirect_uris, created_at) VALUES (?,?,?,?)')
        .run(clientId, clientSecret, JSON.stringify(redirectUris), now());
      return json(res, 201, {
        client_id: clientId,
        client_secret: clientSecret,
        client_id_issued_at: now(),
        client_secret_expires_at: 0,
        redirect_uris: redirectUris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      });
    }

    // --- authorize (GET shows consent, POST verifies passphrase) ---
    if (path === '/authorize' && req.method === 'GET') {
      const p = Object.fromEntries(url.searchParams);
      if (p.code_challenge_method && p.code_challenge_method !== 'S256') {
        return json(res, 400, { error: 'invalid_request', error_description: 'only S256 PKCE supported' });
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders() });
      return res.end(consentPage(p));
    }
    if (path === '/authorize' && req.method === 'POST') {
      const p = parseForm(await readBody(req));
      if (!ADMIN_PASSPHRASE || p.passphrase !== ADMIN_PASSPHRASE) {
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders() });
        return res.end(consentPage(p, 'Incorrect passphrase.'));
      }
      if (!p.redirect_uri || !p.code_challenge) {
        return json(res, 400, { error: 'invalid_request' });
      }
      const code = rand(24);
      db.prepare('INSERT INTO codes (code, client_id, redirect_uri, code_challenge, scope, expires_at) VALUES (?,?,?,?,?,?)')
        .run(code, p.client_id || '', p.redirect_uri, p.code_challenge, p.scope || 'mcp', now() + CODE_TTL);
      const redir = new URL(p.redirect_uri);
      redir.searchParams.set('code', code);
      if (p.state) redir.searchParams.set('state', p.state);
      res.writeHead(302, { Location: redir.toString(), ...corsHeaders() });
      return res.end();
    }

    // --- token ---
    if (path === '/token' && req.method === 'POST') {
      pruneExpired();
      const p = parseForm(await readBody(req));

      if (p.grant_type === 'authorization_code') {
        const row = db.prepare('SELECT * FROM codes WHERE code = ?').get(p.code || '');
        if (!row || row.expires_at < now()) return json(res, 400, { error: 'invalid_grant' });
        db.prepare('DELETE FROM codes WHERE code = ?').run(p.code);
        if (!p.code_verifier || s256(p.code_verifier) !== row.code_challenge) {
          return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
        }
        if (p.redirect_uri && p.redirect_uri !== row.redirect_uri) {
          return json(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
        }
        return issueTokens(res, row.client_id, row.scope);
      }

      if (p.grant_type === 'refresh_token') {
        const row = db.prepare('SELECT * FROM tokens WHERE refresh_token = ?').get(p.refresh_token || '');
        if (!row || row.refresh_expires_at < now()) return json(res, 400, { error: 'invalid_grant' });
        db.prepare('DELETE FROM tokens WHERE access_token = ?').run(row.access_token);
        return issueTokens(res, row.client_id, row.scope, row.refresh_token);
      }

      return json(res, 400, { error: 'unsupported_grant_type' });
    }

    // --- MCP proxy ---
    if (path === '/mcp' || path.startsWith('/mcp/')) {
      const tok = validBearer(req);
      if (!tok) {
        return json(res, 401, { error: 'invalid_token', error_description: 'Authentication required' }, { 'WWW-Authenticate': WWW_AUTH() });
      }
      const bodyBuf = ['GET', 'HEAD'].includes(req.method) ? undefined : await readBody(req);
      return proxyToUpstream(req, res, bodyBuf);
    }

    if (path === '/' || path === '/health') {
      return json(res, 200, { ok: true, service: 'wasender-mcp-oauth-proxy', base: PUBLIC_BASE_URL });
    }

    return json(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error('handler error', e);
    if (!res.headersSent) json(res, 500, { error: 'server_error', error_description: String(e) });
  }
});

function issueTokens(res, clientId, scope, reuseRefresh) {
  const access = rand(32);
  const refresh = reuseRefresh || rand(32);
  const t = now();
  db.prepare(`INSERT INTO tokens (access_token, refresh_token, client_id, scope, access_expires_at, refresh_expires_at)
              VALUES (?,?,?,?,?,?)`)
    .run(access, refresh, clientId, scope || 'mcp', t + ACCESS_TTL, t + REFRESH_TTL);
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

discoverTunnelUrl().finally(() => {
server.listen(PORT, () => {
  console.log(`[wasender-mcp-oauth-proxy] listening on :${PORT}`);
  console.log(`[wasender-mcp-oauth-proxy] PUBLIC_BASE_URL=${PUBLIC_BASE_URL || '(unset)'}`);
  console.log(`[wasender-mcp-oauth-proxy] upstream=${UPSTREAM_MCP_URL}`);
});
});

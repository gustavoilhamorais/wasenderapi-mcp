'use strict';

// End-to-end tests for the OAuth 2.1 (PKCE S256) facade proxy.
// Env must be set BEFORE requiring the server so it picks up a throwaway DB
// and a known passphrase.

const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const TEST_PASSPHRASE = 'correct horse battery staple';
process.env.ADMIN_PASSPHRASE = TEST_PASSPHRASE;
process.env.PUBLIC_BASE_URL = 'http://127.0.0.1';
process.env.DB_PATH = path.join(
  os.tmpdir(),
  `wasender-test-${process.pid}-${crypto.randomBytes(6).toString('hex')}.db`,
);

const { server, db } = require('../src/server.js');

let base;

before(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  db.close();
});

// ---------- helpers ----------
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function registerClient(redirectUris = [REDIRECT]) {
  const res = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uris: redirectUris }),
  });
  assert.equal(res.status, 201);
  return res.json();
}

function form(obj) {
  return new URLSearchParams(obj).toString();
}

async function postForm(path, fields) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form(fields),
    redirect: 'manual',
  });
}

// Run a full authorize POST and return the issued authorization code.
async function authorizeForCode({ client_id, redirect_uri = REDIRECT, challenge, passphrase = TEST_PASSPHRASE }) {
  const res = await postForm('/authorize', {
    client_id,
    redirect_uri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'mcp',
    passphrase,
  });
  assert.equal(res.status, 302, 'authorize should redirect with a code');
  const loc = new URL(res.headers.get('location'));
  return loc.searchParams.get('code');
}

async function exchangeCode({ code, verifier, client_id, redirect_uri = REDIRECT }) {
  return postForm('/token', {
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id,
    redirect_uri,
  });
}

// ---------- tests ----------
test('PKCE S256 authorization_code flow succeeds', async () => {
  const { client_id } = await registerClient();
  const { verifier, challenge } = pkce();
  const code = await authorizeForCode({ client_id, challenge });

  const res = await exchangeCode({ code, verifier, client_id });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.token_type, 'Bearer');
  assert.ok(body.access_token, 'access_token present');
  assert.ok(body.refresh_token, 'refresh_token present');
  assert.equal(body.expires_in, 3600);
});

test('wrong PKCE verifier is rejected', async () => {
  const { client_id } = await registerClient();
  const { challenge } = pkce();
  const code = await authorizeForCode({ client_id, challenge });

  const wrong = crypto.randomBytes(32).toString('base64url');
  const res = await exchangeCode({ code, verifier: wrong, client_id });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'invalid_grant');
});

test('expired authorization code is rejected', async () => {
  const { client_id } = await registerClient();
  const { verifier, challenge } = pkce();
  // Insert a code directly with a past expiry.
  const code = crypto.randomBytes(16).toString('base64url');
  db.prepare('INSERT INTO codes (code, client_id, redirect_uri, code_challenge, scope, expires_at) VALUES (?,?,?,?,?,?)')
    .run(code, client_id, REDIRECT, challenge, 'mcp', Math.floor(Date.now() / 1000) - 60);

  const res = await exchangeCode({ code, verifier, client_id });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_grant');
});

test('bad passphrase returns 401', async () => {
  const { client_id } = await registerClient();
  const { challenge } = pkce();
  const res = await postForm('/authorize', {
    client_id,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    passphrase: 'nope',
  });
  assert.equal(res.status, 401);
});

test('unregistered redirect_uri is rejected at /authorize', async () => {
  const { client_id } = await registerClient([REDIRECT]);
  const { challenge } = pkce();
  const res = await postForm('/authorize', {
    client_id,
    redirect_uri: 'https://evil.example.com/steal',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    passphrase: TEST_PASSPHRASE,
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_request');
});

test('refresh token rotates and the old one cannot be replayed', async () => {
  const { client_id } = await registerClient();
  const { verifier, challenge } = pkce();
  const code = await authorizeForCode({ client_id, challenge });
  const first = await (await exchangeCode({ code, verifier, client_id })).json();

  // First refresh succeeds and returns a NEW refresh token.
  const r1 = await postForm('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id });
  assert.equal(r1.status, 200);
  const rotated = await r1.json();
  assert.ok(rotated.refresh_token);
  assert.notEqual(rotated.refresh_token, first.refresh_token, 'refresh token must rotate');

  // Replaying the ORIGINAL refresh token now fails.
  const replay = await postForm('/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id });
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, 'invalid_grant');

  // The rotated token still works.
  const r2 = await postForm('/token', { grant_type: 'refresh_token', refresh_token: rotated.refresh_token, client_id });
  assert.equal(r2.status, 200);
});

test('oversized request body is rejected with 413', async () => {
  const big = 'x'.repeat(70 * 1024); // > 64 KB
  const res = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [REDIRECT], pad: big }),
  });
  assert.equal(res.status, 413);
  assert.equal((await res.json()).error, 'payload_too_large');
});

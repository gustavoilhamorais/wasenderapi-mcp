# WASenderAPI → Claude.ai MCP Connector

WASenderAPI's hosted MCP (`https://wasenderapi.com/mcp`) only accepts a **static
Bearer token**, which Claude.ai's custom-connector UI refuses (it requires
**OAuth 2.1 + PKCE**). This is a tiny Dockerized **OAuth 2.1 facade proxy** that
sits in front of it: Claude talks OAuth to this proxy, and the proxy injects your
WASenderAPI Personal Access Token (PAT) and forwards traffic upstream.

It is exposed publicly via a **free Cloudflare Quick Tunnel** (`*.trycloudflare.com`).

```
Claude.ai  --OAuth 2.1 + PKCE-->  this proxy  --Bearer PAT-->  wasenderapi.com/mcp
```

## Requirements
- Docker + Docker Compose
- A **paid** WASenderAPI plan + Personal Access Token (MCP needs a paid plan)
- Node 24+ if you want to run the proxy or tests outside Docker (it relies on
  the built-in `node:sqlite`, still experimental — Node prints a one-line
  `ExperimentalWarning` on startup, which is expected)

## Setup
1. Copy the env template and fill in your secrets:
   ```bash
   cp .env.example .env
   ```
   Set in `.env`:
   - `WASENDER_PAT` — your WASenderAPI Personal Access Token.
   - `ADMIN_PASSPHRASE` — the password you'll type on the consent screen.
     You can leave this empty: `scripts/up.sh` generates a strong random
     passphrase, writes it into `.env`, and prints it once — keep it safe. If
     you set your own value, the script leaves it untouched.
   Leave `PUBLIC_BASE_URL` empty — the script fills it in.

2. Bring everything up:
   ```bash
   bash scripts/up.sh
   ```
   This builds the image, starts the proxy + Cloudflare tunnel, detects the public
   `https://<random>.trycloudflare.com` URL, writes it into `.env`, restarts the
   proxy, and prints the exact connector URL.

3. In **Claude.ai → Settings → Connectors → Add custom connector**, paste:
   ```
   https://<random>.trycloudflare.com/mcp
   ```
   Leave the OAuth Client ID/Secret fields blank (Claude auto-registers via DCR).

4. When Claude opens the consent page, enter your `ADMIN_PASSPHRASE`. Done — the
   WASenderAPI WhatsApp tools appear in Claude.

## Important: Quick Tunnel URLs change on restart
The free `*.trycloudflare.com` URL is **ephemeral**. If `cloudflared` restarts, the
URL changes and you must re-run `bash scripts/up.sh` and re-add the new `/mcp` URL
in Claude. For a stable URL, switch `cloudflared` to a **named tunnel** on a
Cloudflare-managed domain.

## Operations
```bash
docker compose ps                      # status
docker compose logs -f oauth-proxy     # proxy logs
docker compose logs -f cloudflared     # tunnel logs / current URL
docker compose down                    # stop
bash scripts/up.sh                     # (re)start + refresh tunnel URL
```
Both services use `restart: unless-stopped`, so they survive reboots/crashes.

## How auth works
- `/.well-known/oauth-protected-resource[/mcp]` — RFC 9728 resource metadata
- `/.well-known/oauth-authorization-server` — RFC 8414 AS metadata (S256 PKCE, DCR)
- `/register` — RFC 7591 Dynamic Client Registration
- `/authorize` — passphrase-gated consent → authorization code
- `/token` — `authorization_code` (PKCE S256) + `refresh_token` grants
- `/mcp` — validates the issued token, swaps in your `WASENDER_PAT`, streams to upstream

State (clients/codes/tokens) is stored in SQLite at `./data/oauth.db`. Only the
**SHA-256 hashes** of access/refresh tokens are persisted, never the raw tokens.

> **Upgrade note:** older builds stored raw tokens. On first start after this
> change the proxy drops the legacy token table (a tolerant migration that
> leaves the rest of `oauth.db` intact), so any tokens issued before the upgrade
> stop working — reconnect once from Claude.ai to get fresh ones.

## Security notes
- `ADMIN_PASSPHRASE` is the only gate on consent. Use a strong value. The
  passphrase check is constant-time, and repeated failures from one IP trigger a
  temporary backoff.
- Authorization is PKCE-only (public client, no `client_secret`). `client_id`
  and `redirect_uri` are validated against the registered client on every
  `/authorize` and `/token` call.
- Refresh tokens rotate on every use; a replayed old refresh token is rejected.
- Your `WASENDER_PAT` lives in `.env` and is injected server-side; Claude never
  sees it.
- `.env` and `data/` are git-ignored.
- To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development
Run the test suite (no dependencies to install — Node 24 built-ins only):
```bash
npm test          # node --test
node --check src/server.js
```

## License
[MIT](LICENSE) © 2026 Gus

#!/usr/bin/env bash
# Bring up the WASenderAPI MCP OAuth proxy + Cloudflare Quick Tunnel,
# discover the public *.trycloudflare.com URL, wire it into .env as
# PUBLIC_BASE_URL, restart the proxy so its discovery docs match, and
# print the exact URL to paste into Claude.ai.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "ERROR: .env not found. Copy .env.example to .env and fill WASENDER_PAT first." >&2
  exit 1
fi

# Ensure an ADMIN_PASSPHRASE exists; generate a strong random one if it is
# missing or empty. An existing value is never overwritten.
if ! grep -qE '^ADMIN_PASSPHRASE=.+' .env; then
  GEN_PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
  if grep -q '^ADMIN_PASSPHRASE=' .env; then
    sed -i "s#^ADMIN_PASSPHRASE=.*#ADMIN_PASSPHRASE=${GEN_PASS}#" .env
  else
    echo "ADMIN_PASSPHRASE=${GEN_PASS}" >> .env
  fi
  echo "==> No ADMIN_PASSPHRASE set; generated a random one and wrote it to .env:"
  echo "      ${GEN_PASS}"
  echo "    Keep it safe — you'll type it on the consent screen."
fi

echo "==> Building and starting stack..."
docker compose up -d --build

echo "==> Waiting for Cloudflare Quick Tunnel URL..."
TUNNEL_URL=""
for i in $(seq 1 30); do
  TUNNEL_URL="$(docker compose logs cloudflared 2>/dev/null \
    | grep -oE 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' \
    | head -n1 || true)"
  [ -n "$TUNNEL_URL" ] && break
  sleep 2
done

if [ -z "$TUNNEL_URL" ]; then
  echo "ERROR: could not detect trycloudflare.com URL. Check: docker compose logs cloudflared" >&2
  exit 1
fi

echo "==> Tunnel URL: $TUNNEL_URL"

# Write/replace PUBLIC_BASE_URL in .env
if grep -q '^PUBLIC_BASE_URL=' .env; then
  sed -i "s#^PUBLIC_BASE_URL=.*#PUBLIC_BASE_URL=${TUNNEL_URL}#" .env
else
  echo "PUBLIC_BASE_URL=${TUNNEL_URL}" >> .env
fi

echo "==> Restarting proxy so discovery docs use the new URL..."
docker compose up -d oauth-proxy

cat <<MSG

============================================================
 WASenderAPI MCP connector is live.

 Paste THIS into Claude.ai > Settings > Connectors >
 "Add custom connector" (Remote MCP server URL):

     ${TUNNEL_URL}/mcp

 When Claude opens the consent page, enter your
 ADMIN_PASSPHRASE from .env.

 NOTE: Quick Tunnel URLs change on cloudflared restart.
 If it changes, re-run this script and re-add the new URL.
============================================================
MSG

# Security Policy

## Reporting a vulnerability

If you discover a security issue in this project, please report it privately.

**Contact:** the repository’s GitHub Security Advisories

Please include:
- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- any suggested remediation.

Please do **not** open a public GitHub issue for security problems. We will
acknowledge your report as soon as possible and keep you updated on the fix.

## Scope

This proxy is the only authentication gate in front of a static-bearer upstream
MCP. The areas most worth scrutiny are:

- the OAuth 2.1 / PKCE authorization and token endpoints,
- the passphrase consent gate and its rate limiting,
- bearer-token validation and the upstream proxy path.

## Operator responsibilities

This software is only as secure as its deployment. Operators should:

- set a strong, unique `ADMIN_PASSPHRASE`,
- keep `WASENDER_PAT` out of version control (it lives in `.env`, which is
  git-ignored),
- rotate `WASENDER_PAT` and `ADMIN_PASSPHRASE` if either may have been exposed,
- expose the proxy **only** through the Cloudflare tunnel. The provided
  `compose.yml` keeps port 8080 on the internal Docker network (`expose`, not
  `ports`). The passphrase rate limit keys off `CF-Connecting-IP`; publishing
  the origin directly to the internet would let a client forge that header, so
  a global attempt ceiling is enforced as a backstop.

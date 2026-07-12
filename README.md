# cms-auth

A tiny, stateless **auth broker for a Git-based CMS** (Decap CMS and other
Netlify-CMS-protocol editors). It lets editors who have **no GitHub account**
sign in with your **OIDC provider** (Authelia) and commit through a **single
shared GitHub App** — with each commit **authored as the signed-in editor**.

The GitHub App credential is minted and held **server-side** and never reaches
the browser.

## Why this exists

Decap's `github` backend normally makes each editor authenticate with their own
GitHub account and commits directly from the browser with that user's token. If
your editors don't (and won't) have GitHub accounts, that model doesn't work.

`cms-auth` replaces it with:

1. **OIDC login.** The CMS opens a popup at `/auth`; the broker runs an OIDC
   authorization-code flow against your provider and reads the editor's identity
   (email + name) from `userinfo`. Optionally it requires a group claim
   (`OIDC_EDITOR_GROUP`) so only editors get in. It hands the CMS a signed,
   short-lived **session token** — not a GitHub credential.
2. **A commit proxy.** The CMS points its `api_root` at `/api`. The broker
   validates the session token, injects a **GitHub App installation token**
   (scoped to the allow-listed repos, `contents:write`, ~1 h, cached), rewrites
   each commit's **author** to the editor (committer stays the bot), and forwards
   to `api.github.com`.

One broker + one GitHub App serves any number of CMS sites: each site points its
config here and is added to `ALLOWED_ORIGINS` and `ALLOWED_REPOS`.

## Endpoints

| Route | Purpose |
| --- | --- |
| `GET /auth` | set state cookie, 302 to the OIDC provider |
| `GET /callback` | verify state, exchange code, read userinfo, mint session, postMessage handshake |
| `/api/*` | validate session, inject App token, stamp author, proxy to GitHub |
| `GET /healthz` | liveness (`200 ok`) |

## Configuration (environment)

| Var | Required | Default | Notes |
| --- | --- | --- | --- |
| `BASE_URL` | ✅ | | public origin of this broker, e.g. `https://cms-auth.example.org`. Redirect URI is `${BASE_URL}/callback`. |
| `ALLOWED_ORIGINS` | ✅ | | comma-separated CMS admin origins (postMessage target **and** CORS allow-list) |
| `ALLOWED_REPOS` | ✅ | | comma-separated `owner/name` the proxy may touch; the installation token is scoped to exactly these |
| `OIDC_ISSUER` | ✅ | | issuer base, e.g. `https://sso.example.org` (endpoints via discovery) |
| `OIDC_CLIENT_ID` | ✅ | | OIDC client id registered with the provider |
| `OIDC_CLIENT_SECRET` | ✅ | | OIDC client secret (confidential client) |
| `OIDC_EDITOR_GROUP` | | | if set, the identity must carry this group claim, else login is refused |
| `OIDC_SCOPES` | | `openid profile email groups` | requested scopes |
| `GITHUB_APP_ID` | ✅ | | the shared GitHub App's id |
| `GITHUB_APP_INSTALLATION_ID` | ✅ | | the App's installation id on your repo(s) |
| `GITHUB_APP_PRIVATE_KEY_FILE` | ✅* | | path to the App private key PEM (preferred; mount as a file) |
| `GITHUB_APP_PRIVATE_KEY` | ✅* | | inline PEM alternative (`*` provide exactly one of file/inline) |
| `COMMITTER_NAME` | | `CMS Bot` | committer name stamped on commits |
| `COMMITTER_EMAIL` | ✅ | | committer email (e.g. the App bot's noreply address) |
| `SESSION_SECRET` | | random | HMAC key for the state cookie + session tokens; **set it** to survive restarts / run replicas |
| `SESSION_TTL` | | `12h` | session-token lifetime (an editing session; the GitHub token is re-minted server-side regardless) |
| `TRUST_FORWARDED` | | `true` | honour `X-Forwarded-For` for rate-limit identity. Safe only behind a proxy that **overwrites** XFF. Set `false` if exposed directly |
| `GITHUB_API_ROOT` | | `https://api.github.com` | upstream API base (override for GHES/tests) |
| `LISTEN_ADDR` | | `:8080` | |

Endpoint overrides `OIDC_AUTH_URL` / `OIDC_TOKEN_URL` / `OIDC_USERINFO_URL` skip
discovery (used in tests / providers without a discovery document).

## Wiring a CMS site to it

In the site's Decap config (`admin/config.yml`):

```yaml
backend:
  name: github
  repo: your-org/your-hugo-site
  branch: main
  base_url: https://cms-auth.example.org   # this broker (OIDC login popup)
  api_root: https://cms-auth.example.org/api  # this broker (commit proxy)
```

Add that site's `admin/` origin to `ALLOWED_ORIGINS` and its repo to
`ALLOWED_REPOS`, and install the GitHub App on that repo.

## GitHub App setup (the shared "bot")

Create one GitHub App (org or user), **Repository permissions → Contents:
Read & write**, install it on each CMS repo, download the private key, and note
the **App ID** and **Installation ID**. There is no bot *user* and no PAT; the
private key stays on the host and the browser never sees a GitHub credential.

## Run

```sh
docker run --rm -p 8080:8080 \
  -e BASE_URL=https://cms-auth.example.org \
  -e ALLOWED_ORIGINS=https://handbook.example.org \
  -e ALLOWED_REPOS=your-org/your-hugo-site \
  -e OIDC_ISSUER=https://sso.example.org \
  -e OIDC_CLIENT_ID=cms-auth -e OIDC_CLIENT_SECRET=… \
  -e OIDC_EDITOR_GROUP=cms-editors \
  -e GITHUB_APP_ID=… -e GITHUB_APP_INSTALLATION_ID=… \
  -e GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/app.pem \
  -e COMMITTER_EMAIL=bot@example.org \
  ghcr.io/uppertoe/cms-auth:latest
```

Image `HEALTHCHECK`: run the binary with `-healthcheck` (probes local `/healthz`).

Stdlib-only Go (no third-party modules); distroless/static image; the GitHub App
JWT is signed with `crypto/rsa`.

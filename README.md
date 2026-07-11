# sveltia-cms-auth

A tiny, stateless **GitHub OAuth relay for [Sveltia CMS](https://github.com/sveltia/sveltia-cms)**
(protocol-compatible with Decap / Netlify CMS external OAuth providers).

Sveltia runs entirely in the browser and commits straight to GitHub. To get a
token it uses GitHub's OAuth *web* flow, whose final `code`→token exchange needs
the OAuth App **client secret** — which can't live in browser JS. This service
holds the secret and performs just that exchange, then hands the token to the
CMS popup via `postMessage`.

**One relay serves every CMS instance.** The token it returns is the editor's
own GitHub token, so it works on any repo they can access. A single GitHub OAuth
App + this one relay backs every Hugo site's CMS — each site just points its
config at the same `base_url`.

## Why not just use an off-the-shelf provider

This one adds a security hardening the common references lack: the token is only
ever `postMessage`'d to an origin on an explicit **allow-list** (`ALLOWED_ORIGINS`
— your CMS admin pages), never to `'*'`. A page that merely opens the popup
cannot receive the token. State is a signed, single-use cookie (CSRF); the
callback page uses a nonce CSP.

## Endpoints

| Route | Purpose |
| --- | --- |
| `GET /auth?provider=github&scope=repo` | set state cookie, 302 to GitHub |
| `GET /callback` | verify state, exchange code, render the postMessage handshake |
| `GET /healthz` | liveness (`200 ok`) |

## Configuration (environment)

| Var | Required | Default | Notes |
| --- | --- | --- | --- |
| `GITHUB_CLIENT_ID` | ✅ | | OAuth App client id |
| `GITHUB_CLIENT_SECRET` | ✅ | | OAuth App client secret |
| `BASE_URL` | ✅ | | public origin of this relay, e.g. `https://cms-auth.example.org` |
| `ALLOWED_ORIGINS` | ✅ | | comma-separated CMS origins allowed to receive a token |
| `ALLOWED_SCOPES` | | `repo,public_repo,user` | scopes a caller may request (each token in a `repo,user` set is checked) |
| `DEFAULT_SCOPE` | | `repo` | used when the caller requests none |
| `STATE_SECRET` | | random | HMAC key for the state cookie; **set it** to survive restarts / run replicas (else in-flight logins drop on restart) |
| `TRUST_FORWARDED` | | `true` | honour `X-Forwarded-For` for rate-limit identity. Safe only behind a proxy that **overwrites** XFF with the true peer. **Set `false` if you expose the relay directly** (no proxy) |
| `LISTEN_ADDR` | | `:8080` | |

The GitHub OAuth App's **Authorization callback URL** must be exactly
`${BASE_URL}/callback`.

## Wiring a Sveltia site to it

In the site's CMS config (`admin/config.yml`):

```yaml
backend:
  name: github
  repo: your-org/your-hugo-site
  branch: main
  base_url: https://cms-auth.example.org   # this relay
  auth_scope: repo                          # or public_repo for public repos
```

Add that site's origin (where `admin/` is served) to the relay's
`ALLOWED_ORIGINS`.

## Run

```sh
docker run --rm -p 8080:8080 \
  -e GITHUB_CLIENT_ID=… -e GITHUB_CLIENT_SECRET=… \
  -e BASE_URL=https://cms-auth.example.org \
  -e ALLOWED_ORIGINS=https://handbook.example.org,https://example.org \
  ghcr.io/uppertoe/sveltia-cms-auth:latest
```

Image `HEALTHCHECK`: run the binary with `-healthcheck` (probes local `/healthz`).

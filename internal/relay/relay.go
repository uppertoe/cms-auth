// Package relay implements cms-auth: a stateless broker that lets a Git-based
// CMS (Decap and other Netlify-CMS-protocol editors) commit through a shared
// GitHub App while editors sign in with an OIDC provider (Authelia) — no
// per-editor GitHub accounts required.
//
// Flow:
//
//	GET /auth      -> set a signed state cookie, 302 to the OIDC provider.
//	GET /callback  -> verify state, exchange the code, read the editor's identity
//	                  from userinfo, mint a signed SESSION token, and hand it to
//	                  the CMS popup's opener via postMessage.
//	/api/*         -> the CMS points its api_root here. Validate the session
//	                  token, inject the shared App installation token (server-side
//	                  only), stamp each commit's author with the editor, proxy to
//	                  GitHub.
//
// The GitHub credential is minted and held server-side and never reaches the
// browser; the token the CMS holds is our session token, meaningful only to this
// broker. The session token is only ever postMessage'd to an origin on an
// explicit allow-list, so a page that merely opened the popup cannot receive it.
package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/uppertoe/cms-auth/internal/config"
)

const stateCookie = "cms_auth_state"
const stateLabel = "cms-auth.state.v1"

type Server struct {
	cfg       *config.Config
	log       *slog.Logger
	oidc      *oidcClient
	ghTokens  *installationTokenMinter
	apiClient *http.Client
	rl        *ipRateLimiter
}

func New(cfg *config.Config, log *slog.Logger) *Server {
	hc := &http.Client{Timeout: 10 * time.Second}
	return &Server{
		cfg: cfg,
		log: log,
		oidc: &oidcClient{
			issuer:       cfg.OIDCIssuer,
			clientID:     cfg.OIDCClientID,
			clientSecret: cfg.OIDCClientSecret,
			redirectURI:  cfg.BaseURL + "/callback",
			scopes:       cfg.OIDCScopes,
			editorGroup:  cfg.OIDCEditorGroup,
			hc:           hc,
			override: oidcEndpoints{
				Authorization: cfg.OIDCAuthURL,
				Token:         cfg.OIDCTokenURL,
				UserInfo:      cfg.OIDCUserInfoURL,
			},
		},
		ghTokens: newInstallationTokenMinter(reqConfig{
			AppID:          cfg.AppID,
			InstallationID: cfg.InstallationID,
			Key:            cfg.AppKey,
			Repos:          cfg.AllowedRepos,
			APIRoot:        cfg.APIRoot,
		}, hc),
		// Separate client for proxied API traffic: no timeout cap so large
		// blob uploads aren't cut off mid-stream (GitHub bounds these itself).
		apiClient: &http.Client{},
		// Public, unauthenticated endpoints (/auth, /callback) are rate-limited;
		// /api is authenticated by the session token and not limited here.
		rl: newIPRateLimiter(30, 8, cfg.TrustForwarded),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /auth", s.rl.limit(s.auth))
	mux.HandleFunc("GET /callback", s.rl.limit(s.callback))
	mux.HandleFunc("/api/", s.proxyAPI)
	mux.HandleFunc("/", s.index)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "ok")
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	baseHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "cms-auth broker. Begin the CMS login at /auth.\n")
}

// auth starts the OIDC dance: stash a signed, single-use state in a cookie and
// redirect the browser to the provider. The CMS opens this in a popup with
// ?provider=github (its backend name); we accept that and ignore any scope.
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Query().Get("provider"); p != "" && p != "github" {
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}
	state, err := randHex(24)
	if err != nil {
		s.log.Error("state generation failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	redirect, err := s.oidc.authRedirectURL(r.Context(), state)
	if err != nil {
		s.log.Error("oidc endpoint resolution failed", "err", err)
		http.Error(w, "auth provider unavailable", http.StatusBadGateway)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    s.signState(state),
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode, // sent on the provider's top-level redirect back
	})
	http.Redirect(w, r, redirect, http.StatusFound)
}

// callback verifies the returned state, exchanges the code for the editor's
// identity, mints a session token, and renders the postMessage handshake page.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	ck, ckErr := r.Cookie(stateCookie)
	// Clear the state cookie in all cases (single use).
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	if ckErr != nil || code == "" || state == "" || !s.validState(ck.Value, state) {
		http.Error(w, "invalid or expired authorization request", http.StatusBadRequest)
		return
	}

	editor, err := s.oidc.exchange(r.Context(), code)
	if err != nil {
		s.log.Warn("oidc exchange failed", "err", err)
		s.renderResult(w, "", "authentication failed")
		return
	}
	editor.Exp = time.Now().Add(s.cfg.SessionTTL).Unix()
	s.log.Info("cms session issued", "email", editor.Email, "name", editor.Name)
	s.renderResult(w, s.mintSession(editor), "")
}

// renderResult writes the popup page that completes the Decap/Netlify handshake.
// The provider stays "github" (the CMS backend name); the token it carries is
// our session token, not a GitHub credential. The page announces readiness to
// the opener; when the opener replies we verify its origin against the allow-list
// before handing the token to that exact origin (never '*').
func (s *Server) renderResult(w http.ResponseWriter, token, errMsg string) {
	var message string
	if errMsg != "" {
		message = "authorization:github:error:" + errMsg
	} else {
		payload, _ := json.Marshal(map[string]string{"token": token, "provider": "github"})
		message = "authorization:github:success:" + string(payload)
	}
	msgJS, _ := json.Marshal(message)
	allowedJS, _ := json.Marshal(s.cfg.AllowedOrigins)

	nonce, err := randHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	baseHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; base-uri 'none'")
	fmt.Fprintf(w, resultHTML, nonce, msgJS, allowedJS)
}

const resultHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorizing…</title>
<style>body{font:15px/1.5 -apple-system,system-ui,sans-serif;margin:3rem;color:#333}</style>
</head><body>
<p id="status">Completing sign-in…</p>
<script nonce="%s">
(function () {
  var MSG = %s;        /* full "authorization:github:…" message */
  var ALLOWED = %s;    /* origins permitted to receive the token */
  function done(t){ var s=document.getElementById('status'); if(s) s.textContent=t; }
  function onMessage(e) {
    if (ALLOWED.indexOf(e.origin) === -1) return;   /* origin allow-list */
    window.removeEventListener('message', onMessage, false);
    window.opener.postMessage(MSG, e.origin);
    done('Done — you can close this window.');
  }
  if (!window.opener) { done('Open this from the CMS, not directly.'); return; }
  window.addEventListener('message', onMessage, false);
  /* announce readiness; the CMS replies and we then target its exact origin */
  window.opener.postMessage('authorizing:github', '*');
})();
</script>
</body></html>`

// --- state cookie signing (CSRF), domain-separated from the session token ---

func (s *Server) signState(state string) string {
	return state + "." + hex.EncodeToString(s.stateMAC(state))
}

func (s *Server) validState(cookieVal, queryState string) bool {
	i := lastDot(cookieVal)
	if i < 0 {
		return false
	}
	got, sigHex := cookieVal[:i], cookieVal[i+1:]
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(sig, s.stateMAC(got)) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(queryState)) == 1
}

func (s *Server) stateMAC(state string) []byte {
	m := hmac.New(sha256.New, s.cfg.SessionSecret)
	m.Write([]byte(stateLabel))
	m.Write([]byte{0})
	m.Write([]byte(state))
	return m.Sum(nil)
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func baseHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

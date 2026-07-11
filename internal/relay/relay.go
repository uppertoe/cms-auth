// Package relay implements a stateless GitHub OAuth relay for Sveltia CMS
// (protocol-compatible with Decap / Netlify CMS external OAuth providers).
//
// Flow:
//
//	GET /auth      -> set a signed state cookie, 302 to GitHub's authorize page.
//	GET /callback  -> verify state, exchange the code for a token server-side
//	                  (using the client secret), then hand the token to the CMS
//	                  popup's opener via postMessage.
//
// One relay + one GitHub OAuth App serves any number of CMS instances: the
// returned token is the editor's own, so it works on every repo they can reach.
//
// Hardening over the common reference providers: the token is only ever
// postMessage'd to an origin on an explicit allow-list (the CMS admin pages),
// so a page that merely opened the popup cannot receive it.
package relay

import (
	"context"
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
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/sveltia-cms-auth/internal/config"
)

const stateCookie = "cms_auth_state"

type Server struct {
	cfg *config.Config
	log *slog.Logger
	hc  *http.Client
}

func New(cfg *config.Config, log *slog.Logger) *Server {
	return &Server{cfg: cfg, log: log, hc: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /auth", s.auth)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("GET /", s.index)
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
	_, _ = io.WriteString(w, "Sveltia CMS GitHub OAuth relay. Begin at /auth?provider=github.\n")
}

// auth starts the OAuth dance: stash a signed, single-use state in a cookie and
// redirect the browser to GitHub.
func (s *Server) auth(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Query().Get("provider"); p != "" && p != "github" {
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}
	scope := r.URL.Query().Get("scope")
	switch {
	case scope == "":
		scope = s.cfg.DefaultScope
	case !contains(s.cfg.AllowedScopes, scope):
		http.Error(w, "scope not allowed", http.StatusBadRequest)
		return
	}

	state, err := randHex(24)
	if err != nil {
		s.log.Error("state generation failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    s.sign(state),
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode, // sent on GitHub's top-level redirect back
	})

	q := url.Values{}
	q.Set("client_id", s.cfg.ClientID)
	q.Set("redirect_uri", s.cfg.BaseURL+"/callback")
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("allow_signup", "false")
	http.Redirect(w, r, s.cfg.AuthURL+"?"+q.Encode(), http.StatusFound)
}

// callback verifies the returned state, exchanges the code for a token using the
// client secret, and renders the postMessage handshake page.
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

	token, err := s.exchange(r.Context(), code)
	if err != nil {
		s.log.Error("token exchange failed", "err", err)
		s.renderResult(w, "", "authentication failed")
		return
	}
	s.renderResult(w, token, "")
}

// exchange performs the server-side code->token POST. GitHub returns JSON when
// asked with Accept: application/json.
func (s *Server) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.BaseURL+"/callback")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("unparsable token response")
	}
	if out.Error != "" {
		return "", fmt.Errorf("github: %s", out.Error)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return out.AccessToken, nil
}

// renderResult writes the popup page that completes the Decap/Netlify handshake.
// The page announces readiness ("authorizing:github") to the opener; when the
// opener replies we verify its origin against the allow-list before handing the
// token to that exact origin (never '*').
func (s *Server) renderResult(w http.ResponseWriter, token, errMsg string) {
	var message string
	if errMsg != "" {
		message = "authorization:github:error:" + errMsg
	} else {
		payload, _ := json.Marshal(map[string]string{"token": token, "provider": "github"})
		message = "authorization:github:success:" + string(payload)
	}
	// json.Marshal produces script-safe literals (escapes < > &), so these are
	// safe to interpolate into the inline <script>.
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

// --- state cookie signing (CSRF) ---

func (s *Server) sign(state string) string {
	m := hmac.New(sha256.New, s.cfg.StateSecret)
	m.Write([]byte(state))
	return state + "." + hex.EncodeToString(m.Sum(nil))
}

func (s *Server) validState(cookieVal, queryState string) bool {
	i := strings.LastIndexByte(cookieVal, '.')
	if i < 0 {
		return false
	}
	got, sig := cookieVal[:i], cookieVal[i+1:]
	m := hmac.New(sha256.New, s.cfg.StateSecret)
	m.Write([]byte(got))
	want := hex.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(queryState)) == 1
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

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

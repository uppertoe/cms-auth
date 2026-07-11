package relay

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/sveltia-cms-auth/internal/config"
)

func newTestServer(t *testing.T, tokenURL string) *Server {
	t.Helper()
	cfg := &config.Config{
		ClientID:       "cid",
		ClientSecret:   "secret",
		BaseURL:        "https://cms-auth.example.org",
		AllowedOrigins: []string{"https://handbook.example.org", "https://example.org"},
		AllowedScopes:  []string{"repo", "public_repo"},
		DefaultScope:   "repo",
		StateSecret:    []byte("test-key-test-key-test-key-32byte"),
		AuthURL:        "https://github.com/login/oauth/authorize",
		TokenURL:       tokenURL,
	}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// auth should set a signed state cookie and redirect to GitHub carrying the same
// state, the configured redirect_uri, and the requested scope.
func TestAuthRedirectsWithStateCookie(t *testing.T) {
	s := newTestServer(t, "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?provider=github&scope=repo", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("client_id") != "cid" {
		t.Errorf("client_id = %q", loc.Query().Get("client_id"))
	}
	if loc.Query().Get("redirect_uri") != "https://cms-auth.example.org/callback" {
		t.Errorf("redirect_uri = %q", loc.Query().Get("redirect_uri"))
	}
	if loc.Query().Get("scope") != "repo" {
		t.Errorf("scope = %q", loc.Query().Get("scope"))
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in redirect")
	}
	ck := cookieByName(rec.Result().Cookies(), stateCookie)
	if ck == nil || !ck.HttpOnly || !ck.Secure {
		t.Fatalf("state cookie missing/insecure: %+v", ck)
	}
	if !s.validState(ck.Value, state) {
		t.Error("cookie does not validate against redirect state")
	}
}

func TestAuthRejectsDisallowedScope(t *testing.T) {
	s := newTestServer(t, "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?scope=admin:org", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAuthRejectsWrongProvider(t *testing.T) {
	s := newTestServer(t, "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?provider=gitlab", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// callback: a valid state + a good token exchange yields an HTML page carrying
// the success message and the origin allow-list, and NOT posting to '*'.
func TestCallbackSuccess(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("client_secret") != "secret" || r.FormValue("code") != "thecode" {
			t.Errorf("bad exchange form: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"gho_abc123","token_type":"bearer","scope":"repo"}`)
	}))
	defer gh.Close()

	s := newTestServer(t, gh.URL)
	state := "statevalue"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=thecode&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: s.sign(state)})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "authorization:github:success:") || !strings.Contains(body, "gho_abc123") {
		t.Errorf("success message missing from body")
	}
	if !strings.Contains(body, "https://handbook.example.org") {
		t.Errorf("allow-list origin missing from body")
	}
	// The token must never be broadcast to '*'.
	if strings.Contains(body, `postMessage(MSG, '*')`) || strings.Contains(body, `postMessage(MSG,"*")`) {
		t.Errorf("token appears to be posted to '*'")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "nonce-") {
		t.Errorf("expected nonce CSP, got %q", csp)
	}
	// state cookie cleared
	if ck := cookieByName(rec.Result().Cookies(), stateCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("state cookie not cleared")
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	s := newTestServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state=one", nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: s.sign("two")}) // different state
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsForgedCookie(t *testing.T) {
	s := newTestServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state=one", nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: "one.deadbeef"}) // bad signature
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// A failed exchange still renders a page (an error handshake), never a token.
func TestCallbackExchangeError(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"error":"bad_verification_code"}`)
	}))
	defer gh.Close()

	s := newTestServer(t, gh.URL)
	state := "st"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=bad&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: s.sign(state)})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (error handshake page)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authorization:github:error:") {
		t.Errorf("expected error handshake in body")
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("token leaked into error page")
	}
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t, "")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func cookieByName(cks []*http.Cookie, name string) *http.Cookie {
	for _, c := range cks {
		if c.Name == name {
			return c
		}
	}
	return nil
}

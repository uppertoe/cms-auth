package relay

import (
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/cms-auth/internal/config"
)

// one RSA key for the whole test binary (generation is the slow part).
var testAppKey *rsa.PrivateKey

func appKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if testAppKey == nil {
		k, err := genTestKey()
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		testAppKey = k
	}
	return testAppKey
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		BaseURL:          "https://cms-auth.example.org",
		AllowedOrigins:   []string{"https://handbook.example.org", "https://example.org"},
		OIDCClientID:     "cms-auth",
		OIDCClientSecret: "oidc-secret",
		OIDCScopes:       "openid profile email groups",
		// dummy overrides so authRedirectURL needs no network in redirect tests
		OIDCAuthURL:     "https://sso.example.org/authorize",
		OIDCTokenURL:    "https://sso.example.org/token",
		OIDCUserInfoURL: "https://sso.example.org/userinfo",
		AppID:           123,
		InstallationID:  456,
		AppKey:          appKey(t),
		AllowedRepos:    []string{"anaes-data-lab/rch-handbooks-hugo"},
		CommitterName:   "RCH Handbook Bot",
		CommitterEmail:  "bot@example.org",
		SessionSecret:   []byte("test-key-test-key-test-key-32byte"),
		SessionTTL:      12 * time.Hour,
		TrustForwarded:  true,
		APIRoot:         "https://api.github.com",
	}
}

func newServer(cfg *config.Config) *Server {
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// --- /auth ---

func TestAuthRedirectsWithStateCookie(t *testing.T) {
	s := newServer(testConfig(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?provider=github&scope=repo", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if got := loc.Query().Get("client_id"); got != "cms-auth" {
		t.Errorf("client_id = %q", got)
	}
	if got := loc.Query().Get("redirect_uri"); got != "https://cms-auth.example.org/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := loc.Query().Get("response_type"); got != "code" {
		t.Errorf("response_type = %q", got)
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

func TestAuthRejectsWrongProvider(t *testing.T) {
	s := newServer(testConfig(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?provider=gitlab", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// --- /callback ---

// stubOIDC serves token + userinfo endpoints. groups controls the userinfo
// response's group claim.
func stubOIDC(t *testing.T, email, name string, groups []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("client_secret") != "oidc-secret" {
			t.Errorf("bad token request: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at_123","token_type":"bearer"}`)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at_123" {
			t.Errorf("userinfo missing bearer: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "u-1", "email": email, "name": name, "groups": groups,
		})
	})
	return httptest.NewServer(mux)
}

func callbackConfig(t *testing.T, oidc *httptest.Server, editorGroup string) *config.Config {
	cfg := testConfig(t)
	cfg.OIDCTokenURL = oidc.URL + "/token"
	cfg.OIDCUserInfoURL = oidc.URL + "/userinfo"
	cfg.OIDCAuthURL = oidc.URL + "/authorize"
	cfg.OIDCEditorGroup = editorGroup
	return cfg
}

func TestCallbackSuccessMintsSession(t *testing.T) {
	oidc := stubOIDC(t, "jane@example.org", "Jane Doe", []string{"cms-editors"})
	defer oidc.Close()
	s := newServer(callbackConfig(t, oidc, "cms-editors"))

	state := "statevalue"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=thecode&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: s.signState(state)})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "authorization:github:success:") {
		t.Errorf("success handshake missing")
	}
	if !strings.Contains(body, "https://handbook.example.org") {
		t.Errorf("allow-list origin missing")
	}
	if strings.Contains(body, `postMessage(MSG, '*')`) || strings.Contains(body, `postMessage(MSG,"*")`) {
		t.Errorf("token posted to '*'")
	}
	// Extract the session token from the embedded message and verify it decodes
	// to the editor identity.
	tok := extractToken(t, body)
	ed, err := s.parseSession(tok)
	if err != nil {
		t.Fatalf("session token invalid: %v", err)
	}
	if ed.Email != "jane@example.org" || ed.Name != "Jane Doe" {
		t.Errorf("editor = %+v", ed)
	}
}

func TestCallbackDeniedByGroup(t *testing.T) {
	oidc := stubOIDC(t, "eve@example.org", "Eve", []string{"other"})
	defer oidc.Close()
	s := newServer(callbackConfig(t, oidc, "cms-editors"))

	state := "st"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=c&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: s.signState(state)})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (error handshake)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authorization:github:error:") {
		t.Errorf("expected error handshake for non-editor")
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	s := newServer(testConfig(t))
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state=one", nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: s.signState("two")})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsForgedCookie(t *testing.T) {
	s := newServer(testConfig(t))
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state=one", nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: "one.deadbeef"})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// --- /healthz ---

func TestHealthz(t *testing.T) {
	s := newServer(testConfig(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

// --- helpers ---

func cookieByName(cks []*http.Cookie, name string) *http.Cookie {
	for _, c := range cks {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// extractToken pulls the session token out of the JSON payload embedded in the
// handshake page (var MSG = "...authorization:github:success:{...}").
func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = "authorization:github:success:"
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no success marker in body")
	}
	// The payload JSON follows the marker up to the closing brace; the whole
	// message is a JS string literal, so find the {...} object.
	rest := body[i+len(marker):]
	start := strings.IndexByte(rest, '{')
	end := strings.IndexByte(rest, '}')
	if start < 0 || end < 0 || end < start {
		t.Fatal("no payload object in message")
	}
	// The embedded JSON escapes quotes for the JS string; unescape minimally.
	raw := strings.ReplaceAll(rest[start:end+1], `\"`, `"`)
	var payload struct {
		Token    string `json:"token"`
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("payload unmarshal: %v (%s)", err, raw)
	}
	if payload.Provider != "github" {
		t.Errorf("provider = %q, want github", payload.Provider)
	}
	return payload.Token
}

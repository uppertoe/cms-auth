package relay

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func genTestKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 2048)
}

// verifyRS256 checks an RS256 signature over signingInput (the raw
// "header.claims" string) using the App public key.
func verifyRS256(key *rsa.PrivateKey, signingInput, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig)
}

// capturedCommit records the author/committer a proxied commit carried.
type capturedCommit struct {
	Author    map[string]string `json:"author"`
	Committer map[string]string `json:"committer"`
	Message   string            `json:"message"`
}

// stubGitHub serves the installation-token endpoint and a commit endpoint that
// records the authorship it received. mintCount counts token mints (for caching).
func stubGitHub(t *testing.T, gotCommit *capturedCommit, mintCount *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/456/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("installation mint missing app jwt")
		}
		*mintCount++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_installation",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_installation" {
			t.Errorf("/user not carrying installation token: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "bot"})
	})
	mux.HandleFunc("/repos/anaes-data-lab/rch-handbooks-hugo/git/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_installation" {
			t.Errorf("commit not carrying installation token")
		}
		if gotCommit != nil {
			_ = json.NewDecoder(r.Body).Decode(gotCommit)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"sha":"newsha"}`)
	})
	return httptest.NewServer(mux)
}

func proxyServer(t *testing.T, gh *httptest.Server) *Server {
	cfg := testConfig(t)
	cfg.APIRoot = gh.URL
	return newServer(cfg)
}

func session(t *testing.T, s *Server, email, name string) string {
	t.Helper()
	return s.mintSession(Editor{Sub: "u1", Email: email, Name: name, Exp: time.Now().Add(time.Hour).Unix()})
}

func TestProxyUnauthorizedWithoutSession(t *testing.T) {
	gh := stubGitHub(t, nil, new(int))
	defer gh.Close()
	s := proxyServer(t, gh)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/user", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestProxyCORSPreflight(t *testing.T) {
	gh := stubGitHub(t, nil, new(int))
	defer gh.Close()
	s := proxyServer(t, gh)

	req := httptest.NewRequest(http.MethodOptions, "/api/repos/anaes-data-lab/rch-handbooks-hugo/contents/x.md", nil)
	req.Header.Set("Origin", "https://handbook.example.org")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://handbook.example.org" {
		t.Errorf("ACAO = %q", got)
	}
}

func TestProxyRejectsDisallowedRepo(t *testing.T) {
	gh := stubGitHub(t, nil, new(int))
	defer gh.Close()
	s := proxyServer(t, gh)

	req := httptest.NewRequest(http.MethodGet, "/api/repos/someone/private/contents/secrets.md", nil)
	req.Header.Set("Authorization", "token "+session(t, s, "jane@example.org", "Jane"))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestProxyPassesThroughUser(t *testing.T) {
	gh := stubGitHub(t, nil, new(int))
	defer gh.Close()
	s := proxyServer(t, gh)

	req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
	req.Header.Set("Authorization", "token "+session(t, s, "jane@example.org", "Jane"))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"login":"bot"`) {
		t.Errorf("unexpected /user body: %s", rec.Body.String())
	}
}

// The headline behaviour: a commit is authored as the editor, committed as the
// bot — even though the CMS only ever held a session token.
func TestProxyStampsEditorAsAuthor(t *testing.T) {
	var got capturedCommit
	gh := stubGitHub(t, &got, new(int))
	defer gh.Close()
	s := proxyServer(t, gh)

	commitBody := `{"message":"Edit page","tree":"treesha","parents":["p1"]}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/repos/anaes-data-lab/rch-handbooks-hugo/git/commits", strings.NewReader(commitBody))
	req.Header.Set("Authorization", "token "+session(t, s, "jane@example.org", "Jane Doe"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if got.Author["email"] != "jane@example.org" || got.Author["name"] != "Jane Doe" {
		t.Errorf("author = %+v, want the editor", got.Author)
	}
	if got.Committer["email"] != "bot@example.org" || got.Committer["name"] != "RCH Handbook Bot" {
		t.Errorf("committer = %+v, want the bot", got.Committer)
	}
	if got.Message != "Edit page" {
		t.Errorf("message mangled: %q", got.Message)
	}
}

func TestInstallationTokenCached(t *testing.T) {
	mints := 0
	gh := stubGitHub(t, nil, &mints)
	defer gh.Close()
	s := proxyServer(t, gh)

	tok := "token " + session(t, s, "jane@example.org", "Jane")
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/user", nil)
		req.Header.Set("Authorization", tok)
		s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	if mints != 1 {
		t.Fatalf("installation token minted %d times, want 1 (cached)", mints)
	}
}

// appJWT is a real RS256 JWT verifiable with the App public key.
func TestAppJWTSignsAndVerifies(t *testing.T) {
	key := appKey(t)
	m := newInstallationTokenMinter(reqConfig{AppID: 99, Key: key, APIRoot: "https://api.github.com"}, http.DefaultClient)
	jwt, err := m.appJWT()
	if err != nil {
		t.Fatalf("appJWT: %v", err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}
	if err := verifyRS256(key, parts[0]+"."+parts[1], parts[2]); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

package relay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// installationTokenMinter turns the shared GitHub App's private key into a
// short-lived installation access token, scoped to the allow-listed repos with
// only the permissions the CMS needs (contents: write). The token is cached and
// reused until shortly before it expires. It is minted and held SERVER-SIDE and
// is never handed to the browser — the API proxy injects it on the way out.
type installationTokenMinter struct {
	cfg reqConfig
	hc  *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// reqConfig is the subset of config the minter needs (kept small for testing).
type reqConfig struct {
	AppID          int64
	InstallationID int64
	Key            *rsa.PrivateKey
	Repos          []string // owner/name
	APIRoot        string
}

func newInstallationTokenMinter(c reqConfig, hc *http.Client) *installationTokenMinter {
	return &installationTokenMinter{cfg: c, hc: hc}
}

// token returns a valid installation token, minting a fresh one if the cache is
// empty or within a minute of expiry.
func (m *installationTokenMinter) get(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Now().Before(m.expires.Add(-time.Minute)) {
		return m.token, nil
	}
	tok, exp, err := m.mint(ctx)
	if err != nil {
		return "", err
	}
	m.token, m.expires = tok, exp
	return tok, nil
}

func (m *installationTokenMinter) mint(ctx context.Context) (string, time.Time, error) {
	jwt, err := m.appJWT()
	if err != nil {
		return "", time.Time{}, err
	}

	// Scope the installation token to exactly the repos we serve, contents:write
	// only — so a leaked token (it never leaves the server, but defence in depth)
	// can do nothing beyond what the CMS itself does.
	repoNames := make([]string, 0, len(m.cfg.Repos))
	for _, r := range m.cfg.Repos {
		if i := strings.LastIndexByte(r, '/'); i >= 0 {
			repoNames = append(repoNames, r[i+1:])
		}
	}
	body, _ := json.Marshal(map[string]any{
		"repositories": repoNames,
		"permissions":  map[string]string{"contents": "write"},
	})

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", m.cfg.APIRoot, m.cfg.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := m.hc.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("installation token: github status %d", resp.StatusCode)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", time.Time{}, fmt.Errorf("installation token: unparsable response")
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = time.Now().Add(time.Hour)
	}
	return out.Token, out.ExpiresAt, nil
}

// appJWT builds and RS256-signs the short (<=10 min) App authentication JWT.
// Pure stdlib — no JWT dependency.
func (m *installationTokenMinter) appJWT() (string, error) {
	now := time.Now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	// iat backdated 60s to tolerate minor clock skew (GitHub's guidance).
	claims := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": m.cfg.AppID,
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)

	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.cfg.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign app jwt: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

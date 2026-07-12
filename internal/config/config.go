// Package config loads and validates the broker's environment configuration.
//
// cms-auth is a small, stateless broker that lets a Git-based CMS (Decap and
// other Netlify-CMS-protocol editors) commit through a SHARED GitHub App,
// while the editor authenticates against an OIDC provider (Authelia here) — so
// editors need no GitHub account of their own. It has two jobs:
//
//   - the OIDC leg (/auth, /callback): log the editor in and mint a signed,
//     short-lived SESSION token carrying their identity (never a GitHub
//     credential), handed to the CMS via the postMessage handshake; and
//   - the API proxy (/api): validate that session token, inject a server-held
//     GitHub App installation token (which never reaches the browser), and
//     stamp each commit's author with the logged-in editor.
//
// Everything it needs comes from the environment; required values are enforced
// at startup so a misconfigured deploy fails loudly instead of insecurely.
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string
	BaseURL    string // public origin of THIS broker, e.g. https://cms-auth.example.org

	// AllowedOrigins is the set of window origins allowed to (a) receive the
	// session token via postMessage and (b) call the API proxy cross-origin
	// (CORS). These are the CMS admin pages, e.g. https://handbook.example.org.
	AllowedOrigins []string

	// --- OIDC (this broker is a confidential client of the provider) ---
	OIDCIssuer       string // e.g. https://sso.example.org (discovery base)
	OIDCClientID     string
	OIDCClientSecret string
	OIDCScopes       string // space-separated; default "openid profile email groups"
	OIDCEditorGroup  string // if set, the identity must carry this group claim

	// Endpoint overrides. Empty means "discover from the issuer". Tests set these
	// directly to point at a stub provider.
	OIDCAuthURL     string
	OIDCTokenURL    string
	OIDCUserInfoURL string

	// --- Shared GitHub App (the "bot"); the private key never leaves the host ---
	AppID          int64
	InstallationID int64
	AppKey         *rsa.PrivateKey

	// AllowedRepos is the owner/name allow-list the proxy will touch. The
	// installation token is scoped to exactly these repositories.
	AllowedRepos []string

	// Committer identity stamped on every commit (author is the editor).
	CommitterName  string
	CommitterEmail string

	// --- Session token (signed, carries the editor identity to the proxy) ---
	SessionSecret          []byte
	SessionSecretEphemeral bool
	SessionTTL             time.Duration

	// TrustForwarded honours X-Forwarded-For for rate-limit client identity.
	// Safe ONLY behind a proxy that OVERWRITES XFF with the true peer (our Caddy
	// cms-auth vhost does). Set false if the broker is exposed directly.
	TrustForwarded bool

	// APIRoot is the upstream GitHub API base (overridable for tests).
	APIRoot string
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:       envOr("LISTEN_ADDR", ":8080"),
		BaseURL:          strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		AllowedOrigins:   splitClean(os.Getenv("ALLOWED_ORIGINS")),
		OIDCIssuer:       strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"),
		OIDCClientID:     os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCScopes:       envOr("OIDC_SCOPES", "openid profile email groups"),
		OIDCEditorGroup:  os.Getenv("OIDC_EDITOR_GROUP"),
		OIDCAuthURL:      os.Getenv("OIDC_AUTH_URL"),
		OIDCTokenURL:     os.Getenv("OIDC_TOKEN_URL"),
		OIDCUserInfoURL:  os.Getenv("OIDC_USERINFO_URL"),
		AllowedRepos:     splitClean(os.Getenv("ALLOWED_REPOS")),
		CommitterName:    envOr("COMMITTER_NAME", "CMS Bot"),
		CommitterEmail:   os.Getenv("COMMITTER_EMAIL"),
		TrustForwarded:   envBool("TRUST_FORWARDED", true),
		APIRoot:          strings.TrimRight(envOr("GITHUB_API_ROOT", "https://api.github.com"), "/"),
	}

	var missing []string
	req := func(name, val string) {
		if val == "" {
			missing = append(missing, name)
		}
	}
	req("BASE_URL", c.BaseURL)
	req("OIDC_ISSUER", c.OIDCIssuer)
	req("OIDC_CLIENT_ID", c.OIDCClientID)
	req("OIDC_CLIENT_SECRET", c.OIDCClientSecret)
	req("COMMITTER_EMAIL", c.CommitterEmail)
	if len(c.AllowedOrigins) == 0 {
		missing = append(missing, "ALLOWED_ORIGINS")
	}
	if len(c.AllowedRepos) == 0 {
		missing = append(missing, "ALLOWED_REPOS")
	}

	if v := os.Getenv("GITHUB_APP_ID"); v == "" {
		missing = append(missing, "GITHUB_APP_ID")
	} else if id, err := strconv.ParseInt(v, 10, 64); err != nil {
		return nil, fmt.Errorf("GITHUB_APP_ID: %w", err)
	} else {
		c.AppID = id
	}
	if v := os.Getenv("GITHUB_APP_INSTALLATION_ID"); v == "" {
		missing = append(missing, "GITHUB_APP_INSTALLATION_ID")
	} else if id, err := strconv.ParseInt(v, 10, 64); err != nil {
		return nil, fmt.Errorf("GITHUB_APP_INSTALLATION_ID: %w", err)
	} else {
		c.InstallationID = id
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}

	// App private key: prefer a mounted file (matches how the estate mounts
	// secrets), fall back to an inline PEM. Parsed once at startup.
	keyPEM, err := loadKeyPEM()
	if err != nil {
		return nil, err
	}
	c.AppKey, err = parseRSAKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY: %w", err)
	}

	for _, r := range c.AllowedRepos {
		if !strings.Contains(strings.Trim(r, "/"), "/") {
			return nil, fmt.Errorf("ALLOWED_REPOS entry %q must be owner/name", r)
		}
	}

	if d := os.Getenv("SESSION_TTL"); d != "" {
		c.SessionTTL, err = time.ParseDuration(d)
		if err != nil {
			return nil, fmt.Errorf("SESSION_TTL: %w", err)
		}
	} else {
		c.SessionTTL = 12 * time.Hour
	}

	// A stable SESSION_SECRET lets the state cookie and session tokens survive a
	// restart (and lets replicas agree); absent one, a random per-process key is
	// fine for a single replica (a restart drops in-flight logins + sessions).
	if s := os.Getenv("SESSION_SECRET"); s != "" {
		c.SessionSecret = []byte(s)
	} else {
		c.SessionSecret = make([]byte, 32)
		if _, err := rand.Read(c.SessionSecret); err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		}
		c.SessionSecretEphemeral = true
	}

	return c, nil
}

// loadKeyPEM reads the App private key from exactly one of:
//   - GITHUB_APP_PRIVATE_KEY_B64: base64 of the PEM (a single-line env value, so
//     it rides safely in a per-app .env — the preferred delivery here, since it
//     reaches the process via the environment regardless of container uid);
//   - GITHUB_APP_PRIVATE_KEY_FILE: a path to a mounted PEM;
//   - GITHUB_APP_PRIVATE_KEY: the raw multi-line PEM inline.
func loadKeyPEM() ([]byte, error) {
	b64 := os.Getenv("GITHUB_APP_PRIVATE_KEY_B64")
	path := os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE")
	inline := os.Getenv("GITHUB_APP_PRIVATE_KEY")

	set := 0
	for _, v := range []string{b64, path, inline} {
		if v != "" {
			set++
		}
	}
	switch {
	case set == 0:
		return nil, fmt.Errorf("missing required env: one of GITHUB_APP_PRIVATE_KEY_B64, GITHUB_APP_PRIVATE_KEY_FILE, GITHUB_APP_PRIVATE_KEY")
	case set > 1:
		return nil, fmt.Errorf("set only one of GITHUB_APP_PRIVATE_KEY_B64, GITHUB_APP_PRIVATE_KEY_FILE, GITHUB_APP_PRIVATE_KEY")
	case b64 != "":
		pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY_B64: %w", err)
		}
		return pem, nil
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY_FILE: %w", err)
		}
		return b, nil
	default:
		return []byte(inline), nil
	}
}

// parseRSAKey accepts a PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") PEM
// block — GitHub issues PKCS#1; some tooling re-wraps it as PKCS#8.
func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#1 or PKCS#8 key: %w", err)
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return rsaKey, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean-ish env var (1/true/yes/on, case-insensitive);
// anything else present is false; absent returns def.
func envBool(k string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func splitClean(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

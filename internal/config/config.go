// Package config loads and validates the relay's environment configuration.
//
// The relay is stateless: everything it needs comes from the environment (the
// GitHub OAuth App credentials, its own public base URL, and the allow-list of
// origins it will hand a token back to). Required values are enforced at
// startup so a misconfigured deploy fails loudly instead of running insecurely.
package config

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ListenAddr string

	ClientID     string // GitHub OAuth App client id
	ClientSecret string // GitHub OAuth App client secret (never leaves the server)
	BaseURL      string // public origin of THIS relay, e.g. https://cms-auth.example.org

	// AllowedOrigins is the set of window origins the token may be postMessage'd
	// to (the CMS admin pages). A token is only ever sent to an origin in this
	// list, so a malicious page that opens the popup cannot receive it.
	AllowedOrigins []string

	AllowedScopes []string // OAuth scopes a caller may request
	DefaultScope  string   // scope used when the caller requests none

	StateSecret []byte // HMAC key for the signed state cookie (CSRF)

	AuthURL  string // GitHub authorize endpoint (overridable for tests)
	TokenURL string // GitHub token endpoint (overridable for tests)
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:     envOr("LISTEN_ADDR", ":8080"),
		ClientID:       os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret:   os.Getenv("GITHUB_CLIENT_SECRET"),
		BaseURL:        strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		AllowedOrigins: splitClean(os.Getenv("ALLOWED_ORIGINS")),
		AllowedScopes:  splitClean(envOr("ALLOWED_SCOPES", "repo,public_repo")),
		DefaultScope:   envOr("DEFAULT_SCOPE", "repo"),
		AuthURL:        envOr("GITHUB_AUTH_URL", "https://github.com/login/oauth/authorize"),
		TokenURL:       envOr("GITHUB_TOKEN_URL", "https://github.com/login/oauth/access_token"),
	}

	var missing []string
	if c.ClientID == "" {
		missing = append(missing, "GITHUB_CLIENT_ID")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "GITHUB_CLIENT_SECRET")
	}
	if c.BaseURL == "" {
		missing = append(missing, "BASE_URL")
	}
	if len(c.AllowedOrigins) == 0 {
		missing = append(missing, "ALLOWED_ORIGINS")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	if !contains(c.AllowedScopes, c.DefaultScope) {
		c.AllowedScopes = append(c.AllowedScopes, c.DefaultScope)
	}

	// A stable STATE_SECRET lets the signed state cookie survive restarts (and
	// lets multiple replicas agree); absent one, a random per-process key is
	// fine for a single replica.
	if s := os.Getenv("STATE_SECRET"); s != "" {
		c.StateSecret = []byte(s)
	} else {
		c.StateSecret = make([]byte, 32)
		if _, err := rand.Read(c.StateSecret); err != nil {
			return nil, fmt.Errorf("generate state secret: %w", err)
		}
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
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

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

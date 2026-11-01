package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func TestLoadKeyPEM_Base64(t *testing.T) {
	pemBytes := testKeyPEM(t)
	t.Setenv("GITHUB_APP_PRIVATE_KEY_B64", base64.StdEncoding.EncodeToString(pemBytes))

	got, err := loadKeyPEM()
	if err != nil {
		t.Fatalf("loadKeyPEM: %v", err)
	}
	if _, err := parseRSAKey(got); err != nil {
		t.Fatalf("parseRSAKey: %v", err)
	}
}

func TestLoadKeyPEM_RejectsMultipleSources(t *testing.T) {
	t.Setenv("GITHUB_APP_PRIVATE_KEY_B64", "x")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "y")
	if _, err := loadKeyPEM(); err == nil {
		t.Fatal("expected error when two key sources are set")
	}
}

func TestLoadKeyPEM_RejectsNone(t *testing.T) {
	if _, err := loadKeyPEM(); err == nil {
		t.Fatal("expected error when no key source is set")
	}
}

func TestParseRSAKey_PKCS8(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := parseRSAKey(pemBytes); err != nil {
		t.Fatalf("PKCS#8 key rejected: %v", err)
	}
}

func setGatewayEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BASE_URL", "https://cms-auth.example.org")
	t.Setenv("ALLOWED_ORIGINS", "https://handbook.example.org")
	t.Setenv("ALLOWED_REPOS", "owner/repo")
	t.Setenv("COMMITTER_EMAIL", "bot@example.org")
	t.Setenv("GITHUB_APP_ID", "1")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "2")
	t.Setenv("GITHUB_APP_PRIVATE_KEY_B64", base64.StdEncoding.EncodeToString(testKeyPEM(t)))
	t.Setenv("AUTH_MODE", "gateway")
	t.Setenv("GATEWAY_SECRET", "gateway-secret-gateway-secret-0123")
	t.Setenv("EDITOR_GROUP", "cms-editors")
}

func TestLoad_GatewayModeNeedsNoOIDC(t *testing.T) {
	setGatewayEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AuthMode != "gateway" || c.EditorGroup != "cms-editors" {
		t.Errorf("config = %+v", c)
	}
}

func TestLoad_GatewayModeRejectsShortSecretOrNoGroup(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("GATEWAY_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Error("expected error for a short GATEWAY_SECRET")
	}
	setGatewayEnv(t)
	t.Setenv("EDITOR_GROUP", "")
	if _, err := Load(); err == nil {
		t.Error("expected error without EDITOR_GROUP")
	}
}

func TestLoad_RejectsUnknownMode(t *testing.T) {
	setGatewayEnv(t)
	t.Setenv("AUTH_MODE", "saml")
	if _, err := Load(); err == nil {
		t.Error("expected error for an unknown AUTH_MODE")
	}
}

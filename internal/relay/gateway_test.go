package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uppertoe/cms-auth/internal/config"
)

const testGatewaySecret = "gateway-secret-gateway-secret-0123"

func gatewayConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.AuthMode = "gateway"
	cfg.GatewaySecret = testGatewaySecret
	cfg.EditorGroup = "cms-editors"
	return cfg
}

func gatewayRequest(headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth?provider=github&scope=repo", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func validGatewayHeaders() map[string]string {
	return map[string]string{
		gatewaySecretHeader: testGatewaySecret,
		gatewayEmailHeader:  "Jane.Citizen@Example.org",
		gatewayGroupsHeader: "user, cms-editors",
	}
}

func TestGatewayAuthMintsSession(t *testing.T) {
	s := newServer(gatewayConfig(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, gatewayRequest(validGatewayHeaders()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "authorization:github:success:") {
		t.Fatalf("success handshake missing")
	}
	ed, err := s.parseSession(extractToken(t, body))
	if err != nil {
		t.Fatalf("session token invalid: %v", err)
	}
	if ed.Email != "jane.citizen@example.org" || ed.Name != "Jane Citizen" {
		t.Errorf("editor = %+v", ed)
	}
}

func TestGatewayAuthRefusals(t *testing.T) {
	cases := map[string]func(h map[string]string){
		"no secret":      func(h map[string]string) { delete(h, gatewaySecretHeader) },
		"wrong secret":   func(h map[string]string) { h[gatewaySecretHeader] = "x" + testGatewaySecret[1:] },
		"no email":       func(h map[string]string) { delete(h, gatewayEmailHeader) },
		"break-glass":    func(h map[string]string) { h[gatewayEmailHeader] = "breakglass:ward-4" },
		"not an address": func(h map[string]string) { h[gatewayEmailHeader] = "jane" },
		"no group":       func(h map[string]string) { h[gatewayGroupsHeader] = "user" },
		"group prefix":   func(h map[string]string) { h[gatewayGroupsHeader] = "cms-editors-old" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer(gatewayConfig(t))
			h := validGatewayHeaders()
			mutate(h)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, gatewayRequest(h))
			body := rec.Body.String()
			if !strings.Contains(body, "authorization:github:error:") || strings.Contains(body, "success") {
				t.Errorf("want an error handshake; body=%s", body)
			}
		})
	}
}

func TestGatewayModeHasNoCallback(t *testing.T) {
	s := newServer(gatewayConfig(t))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?code=x&state=y", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestOIDCModeIgnoresGatewayHeaders(t *testing.T) {
	cfg := testConfig(t)
	cfg.AuthMode = "oidc"
	s := newServer(cfg)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, gatewayRequest(validGatewayHeaders()))
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want the OIDC redirect (302)", rec.Code)
	}
}

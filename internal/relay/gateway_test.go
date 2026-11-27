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
	cfg.EditorRole = "user" // the default Load gives
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
			if !strings.Contains(body, `authorization:github:error:{\"message\":`) {
				t.Errorf("error handshake is not JSON; body=%s", body)
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

// gatewayOutcome runs one /auth request and reports whether a session was
// issued, failing the test if the response is neither handshake.
func gatewayOutcome(t *testing.T, cfg *config.Config, h map[string]string) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	newServer(cfg).Handler().ServeHTTP(rec, gatewayRequest(h))
	body := rec.Body.String()
	switch {
	case strings.Contains(body, "authorization:github:success:"):
		return true
	case strings.Contains(body, "authorization:github:error:"):
		return false
	}
	t.Fatalf("no handshake; status=%d body=%s", rec.Code, body)
	return false
}

func TestGatewayRemoteRolesIgnoredWhenNotTrusted(t *testing.T) {
	// A forged Remote-Roles neither admits someone without the group...
	h := validGatewayHeaders()
	h[gatewayGroupsHeader] = "user"
	h[gatewayRolesHeader] = "user"
	if gatewayOutcome(t, gatewayConfig(t), h) {
		t.Error("forged Remote-Roles admitted an editor with the setting off")
	}
	// ...nor refuses someone with it.
	h = validGatewayHeaders()
	h[gatewayRolesHeader] = "viewer"
	if !gatewayOutcome(t, gatewayConfig(t), h) {
		t.Error("Remote-Roles refused a group member with the setting off")
	}
}

func TestGatewayTrustedRemoteRoles(t *testing.T) {
	cases := []struct {
		name   string
		roles  *string // nil: header absent
		groups string
		want   bool
	}{
		{"user role, no group", ptr("user"), "", true},
		{"user among roles", ptr("admin, user"), "", true},
		{"roles lack user", ptr("admin"), "cms-editors", false},
		{"empty roles", ptr(""), "cms-editors", false},
		{"role prefix", ptr("users"), "cms-editors", false},
		{"no header, group", nil, "cms-editors", true},
		{"no header, no group", nil, "user", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := gatewayConfig(t)
			cfg.TrustRemoteRoles = true
			h := validGatewayHeaders()
			h[gatewayGroupsHeader] = tc.groups
			if tc.roles != nil {
				h[gatewayRolesHeader] = *tc.roles
			}
			if got := gatewayOutcome(t, cfg, h); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGatewayTrustedRemoteRolesEditorRole(t *testing.T) {
	cases := []struct {
		name  string
		roles string
		want  bool
	}{
		{"editor alone", "editor", true},
		{"editor among roles", "admin,editor", true},
		{"editor with spaces", "admin, editor", true},
		{"lacks editor", "user,admin", false},
		{"user alone", "user", false},
		{"empty", "", false},
		{"editor as a prefix", "editors", false},
		{"editor as a suffix", "cms-editor", false},
		{"part of editor", "edit", false},
		{"editor in capitals", "Editor", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := gatewayConfig(t)
			cfg.TrustRemoteRoles = true
			cfg.EditorRole = "editor"
			h := validGatewayHeaders()
			h[gatewayRolesHeader] = tc.roles
			if got := gatewayOutcome(t, cfg, h); got != tc.want {
				t.Errorf("admitted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGatewayEditorRoleIgnoredWhenNotTrusted(t *testing.T) {
	// With TRUST_REMOTE_ROLES off, EDITOR_ROLE changes nothing: the group
	// decides, whatever Remote-Roles says.
	cfg := gatewayConfig(t)
	cfg.EditorRole = "editor"
	h := validGatewayHeaders()
	h[gatewayRolesHeader] = "user"
	if !gatewayOutcome(t, cfg, h) {
		t.Error("a group member was refused with the setting off")
	}
	h = validGatewayHeaders()
	h[gatewayGroupsHeader] = "user"
	h[gatewayRolesHeader] = "editor"
	if gatewayOutcome(t, cfg, h) {
		t.Error("Remote-Roles editor admitted someone without the group with the setting off")
	}
}

func TestGatewayTrustedRemoteRolesWithoutEditorGroup(t *testing.T) {
	cfg := gatewayConfig(t)
	cfg.TrustRemoteRoles = true
	cfg.EditorGroup = ""

	h := validGatewayHeaders()
	h[gatewayRolesHeader] = "user"
	if !gatewayOutcome(t, cfg, h) {
		t.Error("Remote-Roles user refused without EDITOR_GROUP")
	}
	// Without Remote-Roles there is no group to fall back to, so even an
	// empty group list cannot match the empty EDITOR_GROUP.
	for _, groups := range []string{"user, cms-editors", ""} {
		h = validGatewayHeaders()
		h[gatewayGroupsHeader] = groups
		if gatewayOutcome(t, cfg, h) {
			t.Errorf("fallback admitted groups %q without EDITOR_GROUP", groups)
		}
	}
}

func TestGatewaySecretCheckedBeforeRemoteRoles(t *testing.T) {
	cfg := gatewayConfig(t)
	cfg.TrustRemoteRoles = true
	h := validGatewayHeaders()
	h[gatewayRolesHeader] = "user"
	delete(h, gatewaySecretHeader)
	if gatewayOutcome(t, cfg, h) {
		t.Error("Remote-Roles admitted a request without the gateway secret")
	}
}

func ptr(s string) *string { return &s }

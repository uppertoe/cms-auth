package relay

import (
	"crypto/subtle"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Gateway mode: the broker sits behind an authenticating reverse proxy (the
// estate gateway) that signs the editor in before /auth is reached and adds
// Remote-Email and Remote-Groups. The proxy also injects X-Gateway-Secret,
// and the identity headers are trusted only alongside it, so a request that
// reaches the broker any other way cannot assert an identity. The proxy must
// gate /auth only: /api stays authenticated by the session token, because the
// CMS calls it cross-origin without the gateway cookie.
//
// With TRUST_REMOTE_ROLES on, the gateway's role guard is the authority on
// who edits: a Remote-Roles list containing EDITOR_ROLE (by default "user")
// admits the editor, and a Remote-Roles list without it is refused outright. Only when Remote-Roles is
// absent does the broker fall back to EDITOR_GROUP in Remote-Groups. With the
// setting off, Remote-Roles is ignored entirely.

const (
	gatewaySecretHeader = "X-Gateway-Secret"
	gatewayEmailHeader  = "Remote-Email"
	gatewayGroupsHeader = "Remote-Groups"
	gatewayRolesHeader  = "Remote-Roles"
)

// A plain address only: break-glass sessions arrive as "breakglass:<id>".
var gatewayEmailPattern = regexp.MustCompile(`^[^\s@:,]+@[^\s@:,]+\.[^\s@:,]+$`)

func (s *Server) gatewayAuth(w http.ResponseWriter, r *http.Request) {
	if p := r.URL.Query().Get("provider"); p != "" && p != "github" {
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}
	editor, reason := s.gatewayEditor(r)
	if reason != "" {
		s.log.Warn("gateway sign-in refused", "reason", reason)
		s.renderResult(w, "", "authentication failed")
		return
	}
	editor.Exp = time.Now().Add(s.cfg.SessionTTL).Unix()
	s.log.Info("cms session issued", "email", editor.Email, "name", editor.Name)
	s.renderResult(w, s.mintSession(editor), "")
}

// gatewayEditor returns the editor the gateway vouches for, or a reason for
// refusing (for the log only; the browser sees a generic failure).
func (s *Server) gatewayEditor(r *http.Request) (Editor, string) {
	presented := r.Header.Get(gatewaySecretHeader)
	if presented == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.GatewaySecret)) != 1 {
		return Editor{}, "missing or wrong gateway secret"
	}
	if len(r.Header.Values(gatewayEmailHeader)) != 1 {
		return Editor{}, "no single Remote-Email"
	}
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(gatewayEmailHeader)))
	if !gatewayEmailPattern.MatchString(email) {
		return Editor{}, "Remote-Email is not a plain address"
	}
	if reason := s.gatewayEditorRight(r); reason != "" {
		return Editor{}, reason
	}
	return Editor{Sub: email, Email: email, Name: nameFromEmail(email)}, ""
}

// gatewayEditorRight checks that the gateway says this person may edit, by
// Remote-Roles when trusted and present, else by EDITOR_GROUP.
func (s *Server) gatewayEditorRight(r *http.Request) string {
	if s.cfg.TrustRemoteRoles {
		if values := r.Header.Values(gatewayRolesHeader); len(values) > 0 {
			if !containsStr(splitHeaderList(strings.Join(values, ",")), s.cfg.EditorRole) {
				return "Remote-Roles lacks " + s.cfg.EditorRole
			}
			return ""
		}
	}
	if s.cfg.EditorGroup == "" {
		return "no Remote-Roles and no EDITOR_GROUP to fall back to"
	}
	if !containsStr(splitHeaderList(r.Header.Get(gatewayGroupsHeader)), s.cfg.EditorGroup) {
		return "missing editor group"
	}
	return ""
}

func splitHeaderList(v string) []string {
	return strings.FieldsFunc(v, func(c rune) bool {
		return c == ',' || c == ' ' || c == '\t'
	})
}

// nameFromEmail turns "jane.citizen@example.org" into "Jane Citizen" for the
// commit author name; the gateway knows addresses, not display names.
func nameFromEmail(email string) string {
	local := email
	if i := strings.IndexByte(email, '@'); i >= 0 {
		local = email[:i]
	}
	words := strings.FieldsFunc(local, func(c rune) bool { return c == '.' || c == '_' || c == '-' })
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	if len(words) == 0 {
		return local
	}
	return strings.Join(words, " ")
}

package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Editor is the identity the broker learned from the OIDC provider and stamps
// onto commit authorship. It is carried, signed, in the session token the CMS
// holds — it is NEVER taken from anything the client sends unsigned.
type Editor struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Exp   int64  `json:"exp"` // unix seconds
}

// The session token is `base64url(payloadJSON).base64url(hmac)`. It is what the
// CMS receives from /callback and sends back as `Authorization: token <...>` on
// every API-proxy call. It is NOT a GitHub credential: it is only meaningful to
// this broker, so if it leaks it can do nothing except drive this proxy (as that
// editor) until it expires. HMAC domain-separated from the state cookie.
const sessionLabel = "cms-auth.session.v1"

func (s *Server) mintSession(e Editor) string {
	payload, _ := json.Marshal(e)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.sessionMAC(body))
}

// parseSession verifies the signature and expiry, returning the editor identity.
func (s *Server) parseSession(tok string) (Editor, error) {
	var e Editor
	i := strings.LastIndexByte(tok, '.')
	if i < 0 {
		return e, fmt.Errorf("malformed session token")
	}
	body, sigB64 := tok[:i], tok[i+1:]
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return e, fmt.Errorf("malformed signature")
	}
	if subtle.ConstantTimeCompare(sig, s.sessionMAC(body)) != 1 {
		return e, fmt.Errorf("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return e, fmt.Errorf("malformed payload")
	}
	if err := json.Unmarshal(payload, &e); err != nil {
		return e, fmt.Errorf("malformed payload")
	}
	if e.Exp == 0 || time.Now().Unix() >= e.Exp {
		return e, fmt.Errorf("session expired")
	}
	if e.Email == "" {
		return e, fmt.Errorf("session missing email")
	}
	return e, nil
}

func (s *Server) sessionMAC(body string) []byte {
	m := hmac.New(sha256.New, s.cfg.SessionSecret)
	m.Write([]byte(sessionLabel))
	m.Write([]byte{0})
	m.Write([]byte(body))
	return m.Sum(nil)
}

package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxRewriteBody bounds how much of a commit-bearing request body we buffer to
// rewrite authorship. Commit-creation payloads are small (a message + tree sha +
// parents); large content (blobs) goes through a different endpoint and is
// streamed, not buffered. Anything larger than this on a rewrite endpoint is
// rejected rather than silently passed with un-stamped authorship.
const maxRewriteBody = 1 << 20 // 1 MiB

// proxyAPI is the CMS-facing GitHub API proxy. The CMS points its api_root here
// and sends `Authorization: token <session-token>`. We validate that session,
// swap in the shared App installation token (server-side), stamp the commit
// author with the logged-in editor, and forward to GitHub. The App credential
// never reaches the browser.
func (s *Server) proxyAPI(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	s.setCORS(w, origin)

	if r.Method == http.MethodOptions { // CORS preflight
		w.WriteHeader(http.StatusNoContent)
		return
	}

	editor, err := s.editorFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Path after the /api prefix, e.g. /repos/owner/name/git/commits.
	upstreamPath := strings.TrimPrefix(r.URL.Path, "/api")
	if !s.pathAllowed(upstreamPath) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	token, err := s.ghTokens.get(r.Context())
	if err != nil {
		s.log.Error("installation token mint failed", "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Build the outbound request body: rewrite authorship on commit-bearing
	// endpoints, stream everything else unbuffered.
	body, contentLen, err := s.outboundBody(r, upstreamPath, editor)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	target := s.cfg.APIRoot + upstreamPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	copyProxyHeaders(outReq.Header, r.Header)
	outReq.Header.Set("Authorization", "Bearer "+token)
	if outReq.Header.Get("Accept") == "" {
		outReq.Header.Set("Accept", "application/vnd.github+json")
	}
	outReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if contentLen >= 0 {
		outReq.ContentLength = contentLen
		outReq.Header.Set("Content-Length", strconv.FormatInt(contentLen, 10))
	}

	resp, err := s.apiClient.Do(outReq)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		if hopByHop[strings.ToLower(k)] || strings.EqualFold(k, "Access-Control-Allow-Origin") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	s.setCORS(w, origin) // keep our CORS headers authoritative over any upstream echo
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// editorFromRequest validates the session token the CMS sends as
// `Authorization: token <...>` (github backend style) or a Bearer token.
func (s *Server) editorFromRequest(r *http.Request) (Editor, error) {
	auth := r.Header.Get("Authorization")
	tok := ""
	if v, ok := strings.CutPrefix(auth, "token "); ok {
		tok = v
	} else if v, ok := strings.CutPrefix(auth, "Bearer "); ok {
		tok = v
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return Editor{}, errNoToken
	}
	return s.parseSession(tok)
}

// pathAllowed restricts the proxy to the repos we serve plus the few global
// read endpoints the CMS needs to bootstrap. Everything else is denied so the
// injected App token can't be driven beyond the CMS's own surface.
func (s *Server) pathAllowed(p string) bool {
	switch {
	case p == "/user" || p == "/rate_limit" || strings.HasPrefix(p, "/user/"):
		return true
	case strings.HasPrefix(p, "/repos/"):
		rest := strings.TrimPrefix(p, "/repos/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 {
			return false
		}
		repo := parts[0] + "/" + parts[1]
		return containsStr(s.cfg.AllowedRepos, repo)
	default:
		return false
	}
}

// outboundBody returns the body to forward. On commit-bearing endpoints it
// buffers, rewrites author/committer, and returns a fixed length; otherwise it
// returns the original stream and length -1 (chunked/unknown, streamed).
func (s *Server) outboundBody(r *http.Request, upstreamPath string, e Editor) (io.Reader, int64, error) {
	if r.Body == nil || !isCommitEndpoint(r.Method, upstreamPath) {
		return r.Body, -1, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRewriteBody+1))
	if err != nil {
		return nil, 0, err
	}
	if len(raw) > maxRewriteBody {
		return nil, 0, errBodyTooLarge
	}
	rewritten := s.stampAuthorship(raw, e)
	return bytes.NewReader(rewritten), int64(len(rewritten)), nil
}

// stampAuthorship sets author = the editor and committer = the bot on a commit
// payload. If the body isn't the JSON object we expect, it's passed through
// unchanged (GitHub will reject a malformed body itself).
func (s *Server) stampAuthorship(raw []byte, e Editor) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	author, _ := json.Marshal(map[string]string{"name": e.Name, "email": e.Email})
	committer, _ := json.Marshal(map[string]string{"name": s.cfg.CommitterName, "email": s.cfg.CommitterEmail})
	obj["author"] = author
	obj["committer"] = committer
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// isCommitEndpoint matches the calls that carry commit authorship: the Git Data
// API create-commit and the Contents API create/update/delete file.
func isCommitEndpoint(method, p string) bool {
	if !strings.HasPrefix(p, "/repos/") {
		return false
	}
	rest := strings.TrimPrefix(p, "/repos/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 {
		return false
	}
	sub := parts[2]
	switch {
	case method == http.MethodPost && sub == "git/commits":
		return true
	case (method == http.MethodPut || method == http.MethodDelete) && strings.HasPrefix(sub, "contents/"):
		return true
	default:
		return false
	}
}

func (s *Server) setCORS(w http.ResponseWriter, origin string) {
	if origin == "" || !containsStr(s.cfg.AllowedOrigins, origin) {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, If-None-Match, If-Match")
	h.Set("Access-Control-Expose-Headers", "ETag, Link, X-RateLimit-Remaining, X-RateLimit-Reset")
	h.Set("Access-Control-Max-Age", "600")
}

var hopByHop = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
	"authorization": true, // never forward the client's Authorization; we set our own
}

func copyProxyHeaders(dst, src http.Header) {
	for k, vs := range src {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == "host" || lk == "cookie" || lk == "content-length" ||
			lk == "origin" || strings.HasPrefix(lk, "x-forwarded-") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// sentinel errors
var (
	errNoToken      = errString("no session token")
	errBodyTooLarge = errString("request body too large to stamp")
)

type errString string

func (e errString) Error() string { return string(e) }

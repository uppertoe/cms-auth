package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A burst is allowed, then the client is throttled with 429.
func TestRateLimitBurstThenThrottle(t *testing.T) {
	l := newIPRateLimiter(30, 5) // burst 5
	for i := 0; i < 5; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("6th request should be throttled")
	}
	// A different client has its own bucket.
	if !l.allow("5.6.7.8") {
		t.Fatal("a different IP should not be throttled")
	}
}

// The limiter keys on the forwarded client IP, and /auth returns 429 once the
// bucket empties.
func TestAuthRateLimited(t *testing.T) {
	s := newTestServer(t, "")
	s.rl = newIPRateLimiter(30, 2) // tiny burst for the test
	h := s.Handler()

	code := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth?provider=github", nil)
		req.Header.Set("X-Forwarded-For", "9.9.9.9")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := code(); c != http.StatusFound {
		t.Fatalf("1st: got %d want 302", c)
	}
	if c := code(); c != http.StatusFound {
		t.Fatalf("2nd: got %d want 302", c)
	}
	if c := code(); c != http.StatusTooManyRequests {
		t.Fatalf("3rd: got %d want 429", c)
	}
}

func TestClientIPPrefersForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := clientIP(req); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q, want leftmost XFF 203.0.113.7", got)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req2.RemoteAddr = "10.0.0.2:6666"
	if got := clientIP(req2); got != "10.0.0.2" {
		t.Fatalf("clientIP fallback = %q, want 10.0.0.2", got)
	}
}

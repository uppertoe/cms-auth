package relay

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipRateLimiter is a small per-client token-bucket limiter for the public,
// unauthenticated endpoints. /callback triggers an outbound GitHub token
// exchange on every hit, so this bounds how fast one client can drive that (and
// blunts brute abuse of /auth). Stdlib-only, so the service stays dependency-free.
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(perMinute, burst int) *ipRateLimiter {
	l := &ipRateLimiter{
		buckets: make(map[string]*bucket),
		rate:    float64(perMinute) / 60.0,
		burst:   float64(burst),
	}
	go l.cleanupLoop()
	return l
}

// allow debits one token from the caller's bucket, refilling lazily. Returns
// false when the bucket is empty (client is over its rate).
func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[ip]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanupLoop evicts idle buckets so the map can't grow without bound.
func (l *ipRateLimiter) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, b := range l.buckets {
			if b.last.Before(cutoff) {
				delete(l.buckets, ip)
			}
		}
		l.mu.Unlock()
	}
}

// limit wraps a handler, rejecting an over-rate client with 429.
func (l *ipRateLimiter) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// clientIP reads the true client from X-Forwarded-For — Caddy overwrites it with
// the real peer for this vhost (see cms-auth.caddy), so it can't be spoofed —
// falling back to the connection's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

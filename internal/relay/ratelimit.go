package relay

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxBuckets bounds the per-IP map so a flood of distinct keys (e.g. spoofed
// X-Forwarded-For when TrustForwarded is on but no overwriting proxy sits in
// front) cannot grow memory without limit under the container's mem_limit.
const maxBuckets = 50000

// ipRateLimiter is a small per-client token-bucket limiter for the public,
// unauthenticated endpoints. /callback triggers an outbound OIDC token exchange
// on every hit, so this bounds how fast one client can drive that (and blunts
// brute abuse of /auth). Stdlib-only, so the service stays dependency-free.
type ipRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    float64
	trustFwd bool // honour X-Forwarded-For (only safe behind an XFF-overwriting proxy)
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(perMinute, burst int, trustForwarded bool) *ipRateLimiter {
	l := &ipRateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     float64(perMinute) / 60.0,
		burst:    float64(burst),
		trustFwd: trustForwarded,
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
		// Bound the map. Reclaim idle buckets first; if still at capacity, don't
		// track this new key (memory stays bounded) — allow the request rather
		// than deny legitimate traffic during a key-flood.
		if len(l.buckets) >= maxBuckets {
			l.sweepLocked(now.Add(-time.Minute))
			if len(l.buckets) >= maxBuckets {
				return true
			}
		}
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

// sweepLocked evicts buckets idle since before cutoff. Caller holds l.mu.
func (l *ipRateLimiter) sweepLocked(cutoff time.Time) {
	for ip, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}

// cleanupLoop periodically evicts idle buckets so the map can't grow without bound.
func (l *ipRateLimiter) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		l.sweepLocked(time.Now().Add(-10 * time.Minute))
		l.mu.Unlock()
	}
}

// limit wraps a handler, rejecting an over-rate client with 429.
func (l *ipRateLimiter) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r, l.trustFwd)) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// clientIP identifies the caller. When trustForwarded is set (deployed behind a
// proxy that OVERWRITES X-Forwarded-For with the true peer, e.g. our Caddy
// cms-auth vhost), it reads the leftmost XFF; otherwise, and always as a
// fallback, it uses the connection's remote address. Trusting XFF without such
// a proxy lets a client forge its identity — hence the flag defaults on only
// because the shipped deployment guarantees the overwrite.
func clientIP(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

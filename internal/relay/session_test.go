package relay

import (
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	s := newServer(testConfig(t))
	in := Editor{Sub: "u1", Email: "jane@example.org", Name: "Jane Doe", Exp: time.Now().Add(time.Hour).Unix()}
	out, err := s.parseSession(s.mintSession(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Email != in.Email || out.Name != in.Name || out.Sub != in.Sub {
		t.Errorf("roundtrip mismatch: %+v != %+v", out, in)
	}
}

func TestSessionRejectsTamper(t *testing.T) {
	s := newServer(testConfig(t))
	tok := s.mintSession(Editor{Email: "jane@example.org", Exp: time.Now().Add(time.Hour).Unix()})
	// flip a character in the payload segment
	b := []byte(tok)
	b[0] ^= 0x01
	if _, err := s.parseSession(string(b)); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	s := newServer(testConfig(t))
	tok := s.mintSession(Editor{Email: "jane@example.org", Exp: time.Now().Add(-time.Minute).Unix()})
	if _, err := s.parseSession(tok); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestSessionRejectsForeignSecret(t *testing.T) {
	s1 := newServer(testConfig(t))
	cfg2 := testConfig(t)
	cfg2.SessionSecret = []byte("different-secret-different-secret")
	s2 := newServer(cfg2)
	tok := s1.mintSession(Editor{Email: "jane@example.org", Exp: time.Now().Add(time.Hour).Unix()})
	if _, err := s2.parseSession(tok); err == nil {
		t.Fatal("token signed by another secret accepted")
	}
}

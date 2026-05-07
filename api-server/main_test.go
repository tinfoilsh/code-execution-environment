package main

import (
	"net/http"
	"testing"
)

func TestGate_TokenClaimAndMatch(t *testing.T) {
	g := &gate{state: lifecycleWarm}

	// First call claims the token.
	if _, _, ok := g.check("/restore", "tok-1"); !ok {
		t.Fatal("first call should be allowed")
	}
	if g.token != "tok-1" {
		t.Errorf("expected token claimed as %q, got %q", "tok-1", g.token)
	}

	// Subsequent call with the same token passes.
	if _, _, ok := g.check("/exec", "tok-1"); !ok {
		t.Fatal("matching token should be allowed")
	}
}

func TestGate_TokenMismatchReturns403(t *testing.T) {
	g := &gate{state: lifecycleWarm}

	g.check("/restore", "tok-1") // claim

	status, _, ok := g.check("/exec", "tok-2")
	if ok {
		t.Fatal("mismatched token should be rejected")
	}
	if status != http.StatusForbidden {
		t.Errorf("expected 403, got %d", status)
	}
}

func TestGate_LifecycleWarmToActive(t *testing.T) {
	g := &gate{state: lifecycleWarm}

	// Repeated /restore stays in warm (idempotent retry).
	g.check("/restore", "tok")
	g.check("/restore", "tok")
	if g.state != lifecycleWarm {
		t.Errorf("expected warm after /restore calls, got %s", g.state)
	}

	// First non-/restore call flips to active.
	g.check("/exec", "tok")
	if g.state != lifecycleActive {
		t.Errorf("expected active after /exec, got %s", g.state)
	}

	// /restore is now closed.
	status, _, ok := g.check("/restore", "tok")
	if ok {
		t.Fatal("/restore should be rejected once active")
	}
	if status != http.StatusGone {
		t.Errorf("expected 410, got %d", status)
	}
}

func TestGate_LifecycleKilledRejectsEverything(t *testing.T) {
	g := &gate{state: lifecycleWarm}
	g.check("/exec", "tok") // claim + go active
	g.markKilled()

	for _, path := range []string{"/exec", "/read", "/write", "/snapshot", "/restore"} {
		status, _, ok := g.check(path, "tok")
		if ok {
			t.Errorf("%s should be rejected once killed", path)
		}
		if status != http.StatusGone {
			t.Errorf("%s: expected 410, got %d", path, status)
		}
	}
}

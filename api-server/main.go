package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	executorSocket = "/run/execsock/exec.sock"
	// Host portion of the URL is ignored by the unix-socket dialer, but
	// http.NewRequest still needs a syntactically-valid URL.
	executorURL = "http://executor"
)

// 120s budget covers /snapshot and /restore bulk transfers at the
// /workspace tmpfs ceiling (512 MB plaintext → ~683 MB after base64
// in the JSON body). /exec, /read, /write all return in well under a
// second, and the upstream caller (orchestrator) already enforces a
// 35s tool-call cap — proxyHandler propagates that cap via r.Context()
// so this 120s ceiling is just a defense-in-depth backstop.
var executorClient = &http.Client{
	Timeout: 120 * time.Second,
	Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", executorSocket)
		},
	},
}

// Public, always-on paths.
var allowedPaths = map[string]bool{
	"/exec":     true,
	"/read":     true,
	"/write":    true,
	"/snapshot": true,
}

// gate is the container's per-lifetime access policy. Two one-way bits,
// both set lazily by incoming requests:
//
//   - token: empty until the first valid X-Code-Execution-Access-Token
//     claims it; afterwards every call must match or get 403.
//   - restoreOpen: /restore is allowed only while true. Flips false on
//     the first non-/restore call — once user traffic has begun,
//     /restore is dead for the container's lifetime.
//
// They live behind one mutex because every gated call touches both.
// Defense-in-depth pairing: token blocks an attacker hitting a fresh
// warm-pool container before the orchestrator does; restoreOpen blocks
// an attacker injecting a tar after user traffic starts even if the
// token leaks.
type gate struct {
	mu          sync.Mutex
	token       string
	restoreOpen bool
}

var g = &gate{restoreOpen: true}

// check applies the gate to a single request. ok=false means the caller
// should short-circuit with the returned status and error message.
//
// Status mapping (the orchestrator distinguishes these):
//   - 401 missing token   → caller bug, no container teardown
//   - 403 token mismatch  → poisoned container, orchestrator tears down
//   - 410 restore closed  → /restore after user traffic began
func (g *gate) check(path, tok string) (status int, msg string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok == "" {
		return http.StatusUnauthorized, "missing access token", false
	}
	if g.token == "" {
		g.token = tok
	} else if g.token != tok {
		return http.StatusForbidden, "access token mismatch", false
	}
	if path == "/restore" {
		if !g.restoreOpen {
			return http.StatusGone, "restore window closed", false
		}
		// Multiple /restore attempts are fine (transient retries). The
		// window only closes on a non-restore call.
	} else {
		g.restoreOpen = false
	}
	return 0, "", true
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path

	// Reject unknown paths before the gate so they can't claim the token.
	if path != "/restore" && !allowedPaths[path] {
		http.NotFound(w, r)
		return
	}

	if status, msg, ok := g.check(path, r.Header.Get("X-Code-Execution-Access-Token")); !ok {
		log.Printf("api-server: gating %s — %s (%d)", path, msg, status)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error":%q}`, msg)
		return
	}

	// Inherit the inbound request's context so the orchestrator's
	// cancellation/deadline propagates to the executor — otherwise the
	// executor keeps churning on a request whose result is already
	// going to be discarded.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, executorURL+path, r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := executorClient.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"error":"executor unavailable: %s"}`, err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/exec", proxyHandler)
	mux.HandleFunc("/read", proxyHandler)
	mux.HandleFunc("/write", proxyHandler)
	mux.HandleFunc("/snapshot", proxyHandler)
	mux.HandleFunc("/restore", proxyHandler)
	mux.HandleFunc("/health", healthHandler)

	log.Println("api server listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", mux))
}

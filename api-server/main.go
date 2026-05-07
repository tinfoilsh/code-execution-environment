package main

import (
	"context"
	"crypto/subtle"
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

// 120s budget to cover  /snapshot and /restore bulk transfers at the
// /workspace tmpfs ceiling (512 MB plaintext → ~683 MB after base64 in the JSON body).
// It's the responsibility of the upstream caller to enforce a ceiling on eg tool calls
var executorClient = &http.Client{
	Timeout: 120 * time.Second,
	Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", executorSocket)
		},
	},
}

// lifecycle is the container's session state.
//
//   - warm: no user traffic yet. /restore is allowed (idempotent retry);
//     /exec, /read, /write, /snapshot transition to active.
//   - active: user traffic has begun. /restore returns 410; everything
//     else proceeds. A successful /snapshot transitions to killed.
//   - killed: snapshot taken, session over. Every call returns 410.
type lifecycle int

const (
	lifecycleWarm lifecycle = iota
	lifecycleActive
	lifecycleKilled
)

func (l lifecycle) String() string {
	switch l {
	case lifecycleWarm:
		return "warm"
	case lifecycleActive:
		return "active"
	case lifecycleKilled:
		return "killed"
	}
	return "unknown"
}

// gate is the container's per-lifetime access policy
type gate struct {
	mu    sync.Mutex
	token string
	state lifecycle
}

var g = &gate{state: lifecycleWarm}

// check applies the gate to a single request. ok=false means the caller
// should short-circuit with the returned status and error message.
//
// Status
//   - 401 missing token
//   - 403 token mismatch
//   - 410 lifecycle disallows this call
func (g *gate) check(path, tok string) (status int, msg string, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok == "" {
		return http.StatusUnauthorized, "missing access token", false
	}
	if g.token == "" {
		g.token = tok
	} else if subtle.ConstantTimeCompare([]byte(g.token), []byte(tok)) != 1 {
		return http.StatusForbidden, "access token mismatch", false
	}

	switch g.state {
	case lifecycleKilled:
		return http.StatusGone, "container session ended", false
	case lifecycleActive:
		if path == "/restore" {
			return http.StatusGone, "restore window closed", false
		}
	case lifecycleWarm:
		// /restore is idempotent and stays in warm
		if path != "/restore" {
			g.state = lifecycleActive
		}
	}
	return 0, "", true
}

// markKilled is called after a successful /snapshot transfer to close
// the container for any further calls.
func (g *gate) markKilled() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = lifecycleKilled
}

// writeJSONError responds with a JSON {"error": "<msg>"} body and the
// given status. Uses %q so quotes/control characters in msg are escaped.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := r.URL.Path

	if status, msg, ok := g.check(path, r.Header.Get("X-Code-Execution-Access-Token")); !ok {
		log.Printf("api-server: gating %s — %s (%d)", path, msg, status)
		writeJSONError(w, status, msg)
		return
	}

	// Inherit the inbound request's context so the orchestrator's
	// cancellation/deadline propagates to the executor — otherwise the
	// executor keeps churning on a request whose result is already
	// going to be discarded.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, executorURL+path, r.Body)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := executorClient.Do(req)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "executor unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, copyErr := io.Copy(w, resp.Body)

	// A successful /snapshot is the terminal event in the container's
	// lifecycle. Only flip to killed if both the executor returned 200
	// and we streamed the body without error — a mid-stream failure
	// leaves the orchestrator without the snapshot, and it needs the
	// gate open to retry.
	if path == "/snapshot" && resp.StatusCode == http.StatusOK && copyErr == nil {
		g.markKilled()
	}
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

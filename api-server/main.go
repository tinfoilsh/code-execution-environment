package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
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

// restoreOpen is the startup-only gate for /restore.
//
// Behavior: /restore is allowed to be proxied while restoreOpen == 1.
// As soon as ANY non-/restore allowlisted path is hit, the gate flips to
// 0 permanently — once user traffic has begun, restore is dead.
//
// This makes /restore "internal" in the sense that it's only reachable
// during the brief bootstrap window between container start and first
// user request. The orchestrator drops the tar in then; nobody can
// inject one later.
var restoreOpen atomic.Int32

func init() {
	restoreOpen.Store(1)
}

// claimedToken is the access token bound to this container for the rest
// of its lifetime. Empty until the first authenticated call lands; from
// then on, every call must present the same token or get 403.
//
// Pairs with restoreOpen as defense-in-depth: restoreOpen kills the
// "attacker injects a tar after user traffic starts" path even if the
// token leaks; claimedToken kills the "attacker hits a fresh warm-pool
// container before the orchestrator does" path even if the startup
// window is still open.
var (
	tokenMu      sync.Mutex
	claimedToken string
)

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path

	// Reject unknown paths before the token gate so they can't claim.
	if path != "/restore" && !allowedPaths[path] {
		http.NotFound(w, r)
		return
	}

	// Token gate. The first call presenting a non-empty access token
	// claims this container; every later call must match. 401 (missing)
	// vs 403 (mismatch) is intentional — the orchestrator treats the two
	// differently (mismatch tears the container down; missing is a caller
	// bug that wouldn't be helped by tearing down).
	tok := r.Header.Get("X-Code-Execution-Access-Token")
	if tok == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"missing access token"}`)
		return
	}
	tokenMu.Lock()
	if claimedToken == "" {
		claimedToken = tok
	} else if claimedToken != tok {
		tokenMu.Unlock()
		log.Printf("api-server: rejecting %s — access token mismatch", path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"access token mismatch"}`)
		return
	}
	tokenMu.Unlock()

	if path == "/restore" {
		if restoreOpen.Load() == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			fmt.Fprint(w, `{"error":"restore window closed"}`)
			return
		}
		// Note: we do NOT close the gate here on success — multiple
		// restore tries (e.g. retries on transient failure) are fine.
		// The gate closes on the first NON-restore allowlisted call.
	} else {
		// First user-facing call seals restore.
		restoreOpen.Store(0)
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

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

const executorURL = "http://localhost:9000"

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

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path

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
	} else if allowedPaths[path] {
		// First user-facing call seals restore.
		restoreOpen.Store(0)
	} else {
		http.NotFound(w, r)
		return
	}

	client := &http.Client{Timeout: 35 * time.Second}
	req, err := http.NewRequest(http.MethodPost, executorURL+path, r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
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

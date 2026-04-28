package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const executorURL = "http://localhost:9000"

var allowedPaths = map[string]bool{
	"/exec":  true,
	"/read":  true,
	"/write": true,
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !allowedPaths[r.URL.Path] {
		http.NotFound(w, r)
		return
	}

	client := &http.Client{Timeout: 35 * time.Second}
	req, err := http.NewRequest(http.MethodPost, executorURL+r.URL.Path, r.Body)
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
	mux.HandleFunc("/health", healthHandler)

	log.Println("api server listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", mux))
}

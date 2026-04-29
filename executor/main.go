package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

var execMu sync.Mutex

const (
	workspace  = "/workspace"
	socketPath = "/run/execsock/exec.sock"
)

func resolveP(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(workspace, p)
}

type execRequest struct {
	Command string `json:"command"`
}

type execResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type readRequest struct {
	Path string `json:"path"`
}

type readResponse struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type writeRequest struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type writeResponse struct {
	Path string `json:"path"`
	Size int    `json:"size"`
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	execMu.Lock()
	defer execMu.Unlock()

	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Command == "" {
		respondError(w, http.StatusBadRequest, "command is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", req.Command)
	cmd.Dir = workspace

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		respondJSON(w, http.StatusOK, execResponse{
			Stderr:   "command timed out (30s)",
			ExitCode: -1,
		})
		return
	}

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	respondJSON(w, http.StatusOK, execResponse{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		ExitCode: exitCode,
	})
}

func handleRead(w http.ResponseWriter, r *http.Request) {
	var req readRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	resolved := resolveP(req.Path)

	info, err := os.Stat(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			respondError(w, http.StatusNotFound, fmt.Sprintf("file not found: %s", req.Path))
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if info.IsDir() {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("path is a directory: %s", req.Path))
		return
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, readResponse{
		Path:     req.Path,
		Contents: base64.StdEncoding.EncodeToString(data),
	})
}

func handleWrite(w http.ResponseWriter, r *http.Request) {
	var req writeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	resolved := resolveP(req.Path)

	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Contents)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid base64 contents")
		return
	}

	if err := os.WriteFile(resolved, data, 0o644); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, writeResponse{
		Path: req.Path,
		Size: len(data),
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/exec", handleExec)
	mux.HandleFunc("/read", handleRead)
	mux.HandleFunc("/write", handleWrite)
	mux.HandleFunc("/snapshot", handleSnapshot)
	// /restore is reachable on this internal socket. The api-server proxy
	// gates it behind a startup-only flag.
	mux.HandleFunc("/restore", handleRestore)
	mux.HandleFunc("/health", healthHandler)

	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("removing stale socket: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen unix %s: %v", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	log.Printf("executor listening on unix:%s", socketPath)
	log.Fatal(http.Serve(listener, mux))
}

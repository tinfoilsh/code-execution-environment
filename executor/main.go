package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

var execMu sync.Mutex

const workspace = "/workspace"

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

	cmd := exec.Command("bash", "-c", req.Command)
	cmd.Dir = workspace

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	timer := time.AfterFunc(30*time.Second, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})

	err := cmd.Run()
	timedOut := !timer.Stop()

	if timedOut {
		respondJSON(w, http.StatusOK, execResponse{
			Stderr:   "command timed out (30s)",
			ExitCode: -1,
		})
		return
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
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
	if os.IsNotExist(err) {
		respondError(w, http.StatusNotFound, fmt.Sprintf("file not found: %s", req.Path))
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
	mux.HandleFunc("/health", healthHandler)

	log.Println("executor listening on :9000")
	log.Fatal(http.ListenAndServe(":9000", mux))
}

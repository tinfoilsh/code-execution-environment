package main

// /snapshot and /restore handle the workspace tar in plaintext. Encryption
// happens upstream (the orchestrator hands the plaintext tar to tinfoil-buckets,
// which encrypts under the user-supplied symmetric key). The executor never
// sees keys or ciphertext.

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// matches /workspace tmpfs ceiling.
const maxFileBytes = 512 << 20

// snapshotResponse is the plaintext tar of /workspace, base64-encoded.
type snapshotResponse struct {
	Tar string `json:"tar"`
}

// tarWorkspace tars the workspace directory and returns the bytes.
// Includes regular files and directories. Symlinks/devices/etc are skipped.
func tarWorkspace(root string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the root itself.
		if path == root {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() {
			// Skip symlinks/devices/sockets — keeps things simple and
			// matches "we don't allow long-running processes" in spirit.
			return nil
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if mode.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		if mode.IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, f)
			f.Close()
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// untarInto extracts a tar archive into root. Used by /restore.
// Refuses any entry whose resolved path escapes root (path traversal guard).
func untarInto(root string, data []byte) error {
	tr := tar.NewReader(bytes.NewReader(data))
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Sanitize: reject absolute paths and ".." traversal.
		clean := filepath.Clean(hdr.Name)
		if filepath.IsAbs(clean) || clean == ".." {
			return fmt.Errorf("invalid tar entry path: %s", hdr.Name)
		}
		target := filepath.Join(absRoot, clean)
		// Ensure target is still inside root.
		rel, err := filepath.Rel(absRoot, target)
		if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
			return fmt.Errorf("tar entry escapes root: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > maxFileBytes {
				return fmt.Errorf("tar entry %q exceeds %d bytes", hdr.Name, maxFileBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil && err != io.EOF {
				f.Close()
				return err
			}
			f.Close()
		default:
			// Skip symlinks/devices/etc.
		}
	}
	return nil
}

func handleSnapshot(w http.ResponseWriter, r *http.Request) {
	tarBytes, err := tarWorkspace(workspace)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("tar: %v", err))
		return
	}
	respondJSON(w, http.StatusOK, snapshotResponse{
		Tar: base64.StdEncoding.EncodeToString(tarBytes),
	})
}

// --- restore (internal-only, gated) -----------------------------------------

type restoreRequest struct {
	// Tar is the raw plaintext tar bytes, base64-encoded. The orchestrator
	// fetched the snapshot from tinfoil-buckets (which decrypted it under the
	// user-supplied key) before calling this.
	Tar string `json:"tar"`
}

type restoreResponse struct {
	Status string `json:"status"`
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			respondError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("payload exceeds %d bytes", maxErr.Limit))
			return
		}
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Tar == "" {
		respondError(w, http.StatusBadRequest, "tar is required")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Tar)
	if err != nil {
		respondError(w, http.StatusBadRequest, "tar is not valid base64")
		return
	}
	if err := untarInto(workspace, data); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, restoreResponse{Status: "ok"})
}

package main

// /sync-uploads/* manages the /user-uploads tmpfs from the api-server side.
// The model's bash (uid 1001) sees /user-uploads as read-only via FS perms;
// only this executor process (uid 1000) can write to it.
//
// Two-step protocol:
//   1. /sync-uploads/manifest — caller sends desired {filename: sha256};
//      executor deletes anything not in the manifest (or with stale sha)
//      and returns the list of files it doesn't have.
//   2. /sync-uploads/blobs — caller sends bytes for the missing files;
//      executor verifies sha and writes them.
//
// State is held in memory in uploadsState. It only needs to survive within
// a single container's lifetime — /user-uploads is not snapshotted.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

const uploadsDir = "/user-uploads"

// uploadsRoot is the *os.Root handle to /user-uploads. openat2(RESOLVE_BENEATH)
// rejects any path that escapes.
var uploadsRoot *os.Root

// uploadsState maps filename → hex sha256 of file contents currently on disk.
// Protected by uploadsMu. Cleared on container start.
var (
	uploadsMu    sync.Mutex
	uploadsState = map[string]string{}
)

type uploadEntry struct {
	Filename string `json:"filename"`
	Sha256   string `json:"sha256"`
}

type uploadBlob struct {
	Filename string `json:"filename"`
	Sha256   string `json:"sha256"`
	Contents string `json:"contents"` // base64
}

type syncManifestRequest struct {
	Manifest []uploadEntry `json:"manifest"`
}

type syncManifestResponse struct {
	Missing []uploadEntry `json:"missing"`
}

type syncBlobsRequest struct {
	Files []uploadBlob `json:"files"`
}

type syncBlobsResponse struct {
	Written int `json:"written"`
}

func validateUploadFilename(name string) error {
	if name == "" || name == "." {
		return errors.New("filename is required")
	}
	// IsLocal rejects absolute paths and anything that walks outside the
	// root via .. segments — including "../escape" which Clean leaves as-is.
	if !filepath.IsLocal(name) {
		return fmt.Errorf("filename must be a local relative path: %s", name)
	}
	if filepath.Clean(name) != name {
		return fmt.Errorf("filename is not canonical: %s", name)
	}
	return nil
}

func handleSyncUploadsManifest(w http.ResponseWriter, r *http.Request) {
	var req syncManifestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	desired := make(map[string]string, len(req.Manifest))
	for _, entry := range req.Manifest {
		if err := validateUploadFilename(entry.Filename); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if entry.Sha256 == "" {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("sha256 is required for %s", entry.Filename))
			return
		}
		desired[entry.Filename] = entry.Sha256
	}

	uploadsMu.Lock()
	defer uploadsMu.Unlock()

	// Drop anything not in (or stale relative to) the desired manifest.
	for filename, sha := range uploadsState {
		want, ok := desired[filename]
		if ok && want == sha {
			continue
		}
		if err := uploadsRoot.RemoveAll(filename); err != nil && !os.IsNotExist(err) {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("delete %s: %v", filename, err))
			return
		}
		delete(uploadsState, filename)
	}

	missing := []uploadEntry{}
	for filename, sha := range desired {
		if uploadsState[filename] == sha {
			continue
		}
		missing = append(missing, uploadEntry{Filename: filename, Sha256: sha})
	}

	respondJSON(w, http.StatusOK, syncManifestResponse{Missing: missing})
}

func handleSyncUploadsBlobs(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var req syncBlobsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			respondError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("payload exceeds %d bytes", maxErr.Limit))
			return
		}
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	uploadsMu.Lock()
	defer uploadsMu.Unlock()

	for _, blob := range req.Files {
		if err := validateUploadFilename(blob.Filename); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		data, err := base64.StdEncoding.DecodeString(blob.Contents)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid base64 for %s", blob.Filename))
			return
		}
		gotSha := hex.EncodeToString(sha256Sum(data))
		if blob.Sha256 != "" && blob.Sha256 != gotSha {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("sha mismatch for %s: claimed %s, got %s", blob.Filename, blob.Sha256, gotSha))
			return
		}
		if dir := filepath.Dir(blob.Filename); dir != "." {
			if err := uploadsRoot.MkdirAll(dir, 0o755); err != nil {
				respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		// 0o644 → owner (uid 1000) rw, others (incl. bash uid 1001) read-only.
		if err := uploadsRoot.WriteFile(blob.Filename, data, 0o644); err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		uploadsState[blob.Filename] = gotSha
	}

	respondJSON(w, http.StatusOK, syncBlobsResponse{Written: len(req.Files)})
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

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
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
)

// snapshotResponse is the plaintext tar of /workspace, base64-encoded.
type snapshotResponse struct {
	Tar string `json:"tar"`
}

// tarWorkspace tars the contents of root and returns the bytes.
//
// Whitelist: only regular files and directories are written; symlinks,
// FIFOs, sockets, devices are silently dropped.
func tarWorkspace(root *os.Root) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode()
		if !mode.IsRegular() && !mode.IsDir() {
			return nil
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = path
		if mode.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		if mode.IsRegular() {
			f, err := root.Open(path)
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

// untarInto extracts a tar archive into root.
//
// Whitelist: only TypeDir and TypeReg entries are honored; everything
// else (symlinks, hardlinks, devices, FIFOs, future tar types) falls
// through the empty default and is dropped.
//
// Path safety is delegated to *os.Root, which uses openat2 with
// RESOLVE_BENEATH on Linux: any "..", absolute path, or symlink that
// would resolve outside root is refused by the kernel. The total
// payload size is capped upstream by /workspace tmpfs (512 MiB)
func untarInto(root *os.Root, data []byte) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(hdr.Name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(hdr.Name), 0o755); err != nil {
				return err
			}
			f, err := root.OpenFile(hdr.Name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil && err != io.EOF {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

func handleSnapshot(w http.ResponseWriter, r *http.Request) {
	tarBytes, err := tarWorkspace(workspaceRoot)
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
	if err := untarInto(workspaceRoot, data); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, restoreResponse{Status: "ok"})
}

package main

// /snapshot and /restore handle the workspace tar in plaintext. Encryption happens upstream.

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// snapshotResponse exists for test decoding; handleSnapshot frames JSON manually.
type snapshotResponse struct {
	Tar string `json:"tar"`
}

// snapshotTrailer is set to "ok" only on the success path of /snapshot.
const snapshotTrailer = "X-Snapshot-Status"

// Whitelist tar: regular files and directories only
func tarWorkspace(root *os.Root, w io.Writer) error {
	tw := tar.NewWriter(w)

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
		return err
	}
	return tw.Close()
}

// Whitelist untar: TypeDir + TypeReg only. Path escape is caught by
// *os.Root (openat2 RESOLVE_BENEATH); size by the /workspace tmpfs cap.
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

// Streams tar → base64 → response writer so peak RAM is independent
// of workspace size. Status is committed before tar runs; mid-stream
// errors only log and truncate. Manual JSON framing is safe because
// base64.StdEncoding produces no JSON-escapable bytes.
//
// The snapshotTrailer is declared up-front and only set to "ok" once done
func handleSnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Trailer", snapshotTrailer)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `{"tar":"`)
	enc := base64.NewEncoder(base64.StdEncoding, w)
	if err := tarWorkspace(workspaceRoot, enc); err != nil {
		log.Printf("snapshot: %v", err)
		return
	}
	if err := enc.Close(); err != nil {
		log.Printf("snapshot: base64 close: %v", err)
		return
	}
	io.WriteString(w, `"}`)
	w.Header().Set(snapshotTrailer, "ok")
}

type restoreRequest struct {
	// Tar is the raw plaintext tar bytes, base64-encoded.
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

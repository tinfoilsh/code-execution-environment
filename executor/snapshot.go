package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// snapshotRequest carries the user's X25519 public key (raw 32 bytes,
// base64url-encoded). The container generates a fresh DEK each call,
// AES-GCM-encrypts a tar of /workspace under the DEK, and wraps the DEK
// under the user's pubkey via ephemeral-static ECDH + HKDF + AES-GCM.
type snapshotRequest struct {
	Pubkey string `json:"pubkey"`
}

type snapshotResponse struct {
	Ciphertext string `json:"ciphertext"`
	WrappedDEK string `json:"wrappedDEK"`
}

// HKDF info label for deriving the DEK-wrapping key from the X25519 shared
// secret. Distinct from anything else in the system.
const wrapInfo = "tinfoil-exec-snapshot-wrap-v1"

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
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
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

// aesGCMEncrypt seals plaintext under key, returning nonce||ciphertext||tag
// (the standard layout for stdlib AEAD: gcm.Seal appends tag to ciphertext;
// we prepend the nonce).
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// wrapDEK encrypts dek under userPub via ephemeral-static X25519 ECDH +
// HKDF-SHA256 + AES-256-GCM. Returns: ephPub(32) || nonce(12) || ct || tag.
func wrapDEK(userPub, dek []byte) ([]byte, error) {
	curve := ecdh.X25519()
	userKey, err := curve.NewPublicKey(userPub)
	if err != nil {
		return nil, fmt.Errorf("invalid user pubkey: %w", err)
	}
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephPriv.ECDH(userKey)
	if err != nil {
		return nil, err
	}

	// HKDF salt = ephPub || userPub. Binds the wrap to both sides.
	ephPub := ephPriv.PublicKey().Bytes()
	salt := make([]byte, 0, len(ephPub)+len(userPub))
	salt = append(salt, ephPub...)
	salt = append(salt, userPub...)

	wrapKey, err := hkdf.Key(sha256.New, shared, salt, wrapInfo, 32)
	if err != nil {
		return nil, err
	}

	sealed, err := aesGCMEncrypt(wrapKey, dek)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ephPub)+len(sealed))
	out = append(out, ephPub...)
	out = append(out, sealed...)
	return out, nil
}

// snapshot performs the full snapshot pipeline against the given workspace
// root. Pulled out of the handler so unit tests can call it directly.
func snapshot(workspaceRoot string, userPub []byte) (snapshotResponse, error) {
	if len(userPub) != 32 {
		return snapshotResponse{}, fmt.Errorf("pubkey must be 32 bytes, got %d", len(userPub))
	}

	tarBytes, err := tarWorkspace(workspaceRoot)
	if err != nil {
		return snapshotResponse{}, fmt.Errorf("tar: %w", err)
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return snapshotResponse{}, err
	}

	ct, err := aesGCMEncrypt(dek, tarBytes)
	if err != nil {
		return snapshotResponse{}, fmt.Errorf("encrypt tar: %w", err)
	}

	wrapped, err := wrapDEK(userPub, dek)
	if err != nil {
		return snapshotResponse{}, fmt.Errorf("wrap dek: %w", err)
	}

	return snapshotResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
	}, nil
}

func handleSnapshot(w http.ResponseWriter, r *http.Request) {
	var req snapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Pubkey == "" {
		respondError(w, http.StatusBadRequest, "pubkey is required")
		return
	}

	pub, err := base64.RawURLEncoding.DecodeString(req.Pubkey)
	if err != nil {
		// Be lenient: also try standard base64 (with padding) since callers vary.
		pub, err = base64.StdEncoding.DecodeString(req.Pubkey)
		if err != nil {
			respondError(w, http.StatusBadRequest, "pubkey is not valid base64url")
			return
		}
	}
	if len(pub) != 32 {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("pubkey must be 32 bytes, got %d", len(pub)))
		return
	}

	resp, err := snapshot(workspace, pub)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

// --- restore (internal-only, gated) -----------------------------------------

type restoreRequest struct {
	// Tar is the raw plaintext tar bytes, base64-encoded. The orchestrator
	// has already decrypted the snapshot bundle before calling this.
	Tar string `json:"tar"`
}

type restoreResponse struct {
	Status string `json:"status"`
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

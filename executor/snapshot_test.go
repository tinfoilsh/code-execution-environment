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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: unwrap a wrappedDEK using the user's X25519 private key.
// Mirrors the wrapDEK layout: ephPub(32) || nonce(12) || ct || tag.
func unwrapDEK(t *testing.T, userPriv *ecdh.PrivateKey, wrapped []byte) []byte {
	t.Helper()
	if len(wrapped) < 32+12+16 {
		t.Fatalf("wrapped too short: %d", len(wrapped))
	}
	curve := ecdh.X25519()
	ephPubBytes := wrapped[:32]
	rest := wrapped[32:]

	ephPub, err := curve.NewPublicKey(ephPubBytes)
	if err != nil {
		t.Fatalf("parse ephPub: %v", err)
	}
	shared, err := userPriv.ECDH(ephPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	userPub := userPriv.PublicKey().Bytes()
	salt := append(append([]byte{}, ephPubBytes...), userPub...)

	wrapKey, err := hkdf.Key(sha256.New, shared, salt, wrapInfo, 32)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := rest[:gcm.NonceSize()]
	ct := rest[gcm.NonceSize():]
	dek, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("open wrappedDEK: %v", err)
	}
	if len(dek) != 32 {
		t.Fatalf("dek wrong size: %d", len(dek))
	}
	return dek
}

// helper: AES-GCM open of nonce||ct||tag.
func gcmOpen(t *testing.T, key, blob []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := blob[:gcm.NonceSize()]
	ct := blob[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("gcm open: %v", err)
	}
	return pt
}

// readTar collects {path: contents} for regular files in a tar blob.
func readTar(t *testing.T, data []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("tar read body: %v", err)
			}
			out[hdr.Name] = string(b)
		}
	}
	return out
}

// TestSnapshotRoundTrip is the headline test: take a snapshot of a temp
// "workspace", manually unwrap the DEK, decrypt the tar, verify file
// contents match what was on disk.
func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"hello.txt":         "hello world",
		"sub/nested.go":     "package nested",
		"sub/deep/data.bin": "binary-ish\x00\x01\x02 contents",
	}
	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	curve := ecdh.X25519()
	userPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub := userPriv.PublicKey().Bytes()

	resp, err := snapshot(dir, userPub)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	wrapped, err := base64.StdEncoding.DecodeString(resp.WrappedDEK)
	if err != nil {
		t.Fatalf("decode wrappedDEK: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	dek := unwrapDEK(t, userPriv, wrapped)
	tarBytes := gcmOpen(t, dek, ct)
	got := readTar(t, tarBytes)

	for rel, want := range files {
		if got[rel] != want {
			t.Errorf("file %q: got %q, want %q", rel, got[rel], want)
		}
	}
}

func TestSnapshotEmptyWorkspace(t *testing.T) {
	dir := t.TempDir()
	curve := ecdh.X25519()
	userPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := snapshot(dir, userPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(resp.WrappedDEK)
	ct, _ := base64.StdEncoding.DecodeString(resp.Ciphertext)
	dek := unwrapDEK(t, userPriv, wrapped)
	tarBytes := gcmOpen(t, dek, ct)
	got := readTar(t, tarBytes)
	if len(got) != 0 {
		t.Errorf("expected empty tar, got %d entries", len(got))
	}
}

func TestSnapshotRejectsBadPubkeyShort(t *testing.T) {
	_, err := snapshot(t.TempDir(), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short pubkey")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("expected size error, got %v", err)
	}
}

func TestHandleSnapshotRejectsMalformedPubkey(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", `{"pubkey":""}`},
		{"not_b64", `{"pubkey":"!!!not base64!!!"}`},
		{"wrong_size", `{"pubkey":"` + base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) + `"}`},
		{"invalid_json", `not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/snapshot", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			handleSnapshot(w, r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleSnapshotAcceptsValidPubkey(t *testing.T) {
	// Use a fake workspace by overriding via a small subdir snapshot test
	// (handler hits the real `workspace` const, so just check it returns
	// a parseable response shape if the const path exists; otherwise skip).
	if _, err := os.Stat(workspace); err != nil {
		t.Skipf("no %s on this machine: %v", workspace, err)
	}
	curve := ecdh.X25519()
	userPriv, _ := curve.GenerateKey(rand.Reader)
	pub := base64.RawURLEncoding.EncodeToString(userPriv.PublicKey().Bytes())

	body, _ := json.Marshal(snapshotRequest{Pubkey: pub})
	r := httptest.NewRequest(http.MethodPost, "/snapshot", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleSnapshot(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp snapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Ciphertext == "" || resp.WrappedDEK == "" {
		t.Errorf("missing fields: %+v", resp)
	}
}

// TestRestoreRoundTrip: tar a directory, hand it to handleRestore, verify
// the files land in /workspace. Skips if /workspace isn't writable here.
func TestRestoreRoundTrip(t *testing.T) {
	if _, err := os.Stat(workspace); err != nil {
		t.Skipf("no %s on this machine: %v", workspace, err)
	}
	// Build a tar with one file.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("restored!")
	hdr := &tar.Header{
		Name:     "restore-test-file.txt",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	target := filepath.Join(workspace, "restore-test-file.txt")
	defer os.Remove(target)

	req := restoreRequest{Tar: base64.StdEncoding.EncodeToString(buf.Bytes())}
	jb, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/restore", bytes.NewReader(jb))
	w := httptest.NewRecorder()
	handleRestore(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("contents mismatch: got %q, want %q", got, body)
	}
}

func TestUntarRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name:     "../escape.txt",
		Mode:     0o644,
		Size:     3,
		Typeflag: tar.TypeReg,
	}
	tw.WriteHeader(hdr)
	tw.Write([]byte("bad"))
	tw.Close()

	if err := untarInto(dir, buf.Bytes()); err == nil {
		t.Error("expected path traversal to be rejected")
	}
}

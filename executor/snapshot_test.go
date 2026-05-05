package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

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

// TestTarWorkspaceRoundTrip writes some files under a temp workspace, tars
// them via tarWorkspace, then verifies the contents round-trip.
func TestTarWorkspaceRoundTrip(t *testing.T) {
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

	tarBytes, err := tarWorkspace(dir)
	if err != nil {
		t.Fatalf("tarWorkspace: %v", err)
	}

	got := readTar(t, tarBytes)
	for rel, want := range files {
		if got[rel] != want {
			t.Errorf("file %q: got %q, want %q", rel, got[rel], want)
		}
	}
}

func TestTarWorkspaceEmpty(t *testing.T) {
	dir := t.TempDir()
	tarBytes, err := tarWorkspace(dir)
	if err != nil {
		t.Fatalf("tarWorkspace: %v", err)
	}
	got := readTar(t, tarBytes)
	if len(got) != 0 {
		t.Errorf("expected empty tar, got %d entries", len(got))
	}
}

// TestHandleSnapshotReturnsTar exercises the HTTP handler against the real
// workspace constant. Skips when /workspace doesn't exist on the host.
func TestHandleSnapshotReturnsTar(t *testing.T) {
	if _, err := os.Stat(workspace); err != nil {
		t.Skipf("no %s on this machine: %v", workspace, err)
	}
	r := httptest.NewRequest(http.MethodPost, "/snapshot", nil)
	w := httptest.NewRecorder()
	handleSnapshot(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp snapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Tar == "" {
		t.Errorf("missing tar field: %+v", resp)
	}
	if _, err := base64.StdEncoding.DecodeString(resp.Tar); err != nil {
		t.Errorf("tar field is not valid base64: %v", err)
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

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

// TestMain initializes the workspaceRoot global when /workspace exists on
// the host, so the handler-level tests (TestHandleSnapshotReturnsTar,
// TestRestoreRoundTrip) can exercise handleSnapshot/handleRestore which
// read it. When /workspace is absent (typical dev machine) those tests
// skip and workspaceRoot is left nil.
func TestMain(m *testing.M) {
	if _, err := os.Stat(workspace); err == nil {
		root, err := os.OpenRoot(workspace)
		if err != nil {
			panic(err)
		}
		workspaceRoot = root
		defer root.Close()
	}
	os.Exit(m.Run())
}

// openTestRoot opens t.TempDir() as an *os.Root and registers a Close
// cleanup. Mirrors how main() opens workspaceRoot, so unit tests exercise
// the same code path as production.
func openTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// tarWorkspaceBytes adapts the streaming tarWorkspace for tests that
// want the bytes in hand.
func tarWorkspaceBytes(t *testing.T, root *os.Root) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := tarWorkspace(root, &buf); err != nil {
		t.Fatalf("tarWorkspace: %v", err)
	}
	return buf.Bytes()
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

// TestTarWorkspaceRoundTrip writes some files under a temp workspace, tars
// them via tarWorkspace, then verifies the contents round-trip.
func TestTarWorkspaceRoundTrip(t *testing.T) {
	root := openTestRoot(t)
	dir := root.Name()

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

	tarBytes := tarWorkspaceBytes(t, root)
	got := readTar(t, tarBytes)
	for rel, want := range files {
		if got[rel] != want {
			t.Errorf("file %q: got %q, want %q", rel, got[rel], want)
		}
	}
}

func TestTarWorkspaceEmpty(t *testing.T) {
	root := openTestRoot(t)
	tarBytes := tarWorkspaceBytes(t, root)
	got := readTar(t, tarBytes)
	if len(got) != 0 {
		t.Errorf("expected empty tar, got %d entries", len(got))
	}
}

// TestTarWorkspaceSkipsSymlinks verifies the whitelist: a symlink in the
// workspace must not appear in the tar at all (neither as a symlink entry
// nor as a regular file with the symlink target's contents).
func TestTarWorkspaceSkipsSymlinks(t *testing.T) {
	root := openTestRoot(t)
	dir := root.Name()

	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	// In-workspace symlink — should be skipped (not even a symlink entry).
	if err := os.Symlink("real.txt", filepath.Join(dir, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	// Out-of-workspace symlink — definitely should be skipped.
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "passwd")); err != nil {
		t.Fatal(err)
	}

	tarBytes := tarWorkspaceBytes(t, root)

	tr := tar.NewReader(bytes.NewReader(tarBytes))
	names := map[string]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		names[hdr.Name] = hdr.Typeflag
	}
	if _, ok := names["alias.txt"]; ok {
		t.Errorf("alias.txt should have been skipped, got typeflag %c", names["alias.txt"])
	}
	if _, ok := names["passwd"]; ok {
		t.Errorf("passwd symlink should have been skipped, got typeflag %c", names["passwd"])
	}
	if names["real.txt"] != tar.TypeReg {
		t.Errorf("real.txt missing or wrong type: %v", names)
	}
}

// Exercises handleSnapshot's manual JSON framing end-to-end.
// Swaps workspaceRoot so it runs on dev machines.
func TestHandleSnapshotStreaming(t *testing.T) {
	root := openTestRoot(t)
	if err := os.WriteFile(filepath.Join(root.Name(), "hello.txt"), []byte("streamed"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := workspaceRoot
	workspaceRoot = root
	defer func() { workspaceRoot = prev }()

	r := httptest.NewRequest(http.MethodPost, "/snapshot", nil)
	w := httptest.NewRecorder()
	handleSnapshot(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp snapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v: body=%q", err, w.Body.String())
	}
	tarBytes, err := base64.StdEncoding.DecodeString(resp.Tar)
	if err != nil {
		t.Fatalf("tar field is not valid base64: %v", err)
	}
	if got := readTar(t, tarBytes); got["hello.txt"] != "streamed" {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
}

// TestRestoreRoundTrip: tar a directory, hand it to handleRestore, verify
// the files land in /workspace. Skips if /workspace isn't writable here.
func TestRestoreRoundTrip(t *testing.T) {
	if workspaceRoot == nil {
		t.Skipf("no %s on this machine", workspace)
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

// TestRestoreReplacesWorkspace verifies /restore is authoritative,
// not additive: files that exist before the restore but not in the
// incoming tar are gone afterwards.
func TestRestoreReplacesWorkspace(t *testing.T) {
	root := openTestRoot(t)
	dir := root.Name()

	// Pre-existing junk that should NOT survive the restore.
	if err := os.WriteFile(filepath.Join(dir, "stale.txt"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "stale-subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stale-subdir", "nested.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Tar containing only fresh.txt.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("fresh")
	if err := tw.WriteHeader(&tar.Header{
		Name: "fresh.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()

	if err := restoreInto(root, buf.Bytes()); err != nil {
		t.Fatalf("restoreInto: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "stale.txt")); !os.IsNotExist(err) {
		t.Errorf("stale.txt should have been removed; stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "stale-subdir")); !os.IsNotExist(err) {
		t.Errorf("stale-subdir should have been removed; stat err = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fresh.txt"))
	if err != nil {
		t.Fatalf("read fresh.txt: %v", err)
	}
	if string(got) != "fresh" {
		t.Errorf("fresh.txt: got %q, want %q", got, "fresh")
	}
}

func TestUntarRejectsPathTraversal(t *testing.T) {
	root := openTestRoot(t)

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

	if err := untarInto(root, buf.Bytes()); err == nil {
		t.Error("expected path traversal to be rejected")
	}
}

// TestUntarRejectsSymlinkEscape verifies that the kernel-level os.Root
// guard (RESOLVE_BENEATH) blocks an attempt to write through a symlink
// that was planted in the workspace before restore.
//
// This is the attack the hardening exists for: a symlink to /etc/passwd
// gets dropped into /workspace (e.g. by a prior /exec), then a tar entry
// for that name tries to write through it. With os.Root, the file open
// fails because /etc/passwd is outside the root.
func TestUntarRejectsSymlinkEscape(t *testing.T) {
	root := openTestRoot(t)
	dir := root.Name()

	// Plant a symlink that targets outside the workspace root.
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "victim")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("attacker controlled")
	hdr := &tar.Header{
		Name:     "victim",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}
	tw.WriteHeader(hdr)
	tw.Write(body)
	tw.Close()

	if err := untarInto(root, buf.Bytes()); err == nil {
		t.Error("expected open through escaping symlink to be rejected")
	}

	// Verify /etc/passwd is unchanged (would require root anyway, but the
	// open should have failed before any write).
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		if bytes.Contains(data, body) {
			t.Fatalf("/etc/passwd was modified by the test! contents: %s", data)
		}
	}
}

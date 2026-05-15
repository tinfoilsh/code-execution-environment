package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// setupUploadsTest swaps uploadsRoot to a temp dir and clears uploadsState
// for the duration of one test, restoring both at cleanup. Mirrors how
// main() opens uploadsRoot.
func setupUploadsTest(t *testing.T) {
	t.Helper()
	root := openTestRoot(t) // registers Close cleanup
	prevRoot := uploadsRoot
	prevState := uploadsState
	uploadsRoot = root
	uploadsState = map[string]string{}
	t.Cleanup(func() {
		uploadsRoot = prevRoot
		uploadsState = prevState
	})
}

func postManifest(t *testing.T, manifest []uploadEntry) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(syncManifestRequest{Manifest: manifest})
	r := httptest.NewRequest(http.MethodPost, "/sync-uploads/manifest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleSyncUploadsManifest(w, r)
	return w
}

func postBlobs(t *testing.T, files []uploadBlob) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(syncBlobsRequest{Files: files})
	r := httptest.NewRequest(http.MethodPost, "/sync-uploads/blobs", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleSyncUploadsBlobs(w, r)
	return w
}

func shaHex(s string) string {
	return hex.EncodeToString(sha256Sum([]byte(s)))
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestValidateUploadFilename(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"plain", "report.pdf", false},
		{"nested", "subdir/data.csv", false},
		{"empty", "", true},
		{"absolute", "/etc/passwd", true},
		{"dot", ".", true},
		{"dot-dot", "..", true},
		{"escape", "../escape", true},
		{"trailing-slash", "report.pdf/", true}, // not canonical
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUploadFilename(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateUploadFilename(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestSyncUploadsManifestEmpty(t *testing.T) {
	setupUploadsTest(t)

	w := postManifest(t, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp syncManifestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Missing) != 0 {
		t.Errorf("expected no missing, got %+v", resp.Missing)
	}
}

func TestSyncUploadsManifestAllMissing(t *testing.T) {
	setupUploadsTest(t)

	manifest := []uploadEntry{
		{Filename: "a.txt", Sha256: shaHex("a")},
		{Filename: "b.txt", Sha256: shaHex("b")},
	}
	w := postManifest(t, manifest)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp syncManifestResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Missing) != 2 {
		t.Fatalf("expected 2 missing, got %+v", resp.Missing)
	}
	got := map[string]string{}
	for _, m := range resp.Missing {
		got[m.Filename] = m.Sha256
	}
	if got["a.txt"] != shaHex("a") || got["b.txt"] != shaHex("b") {
		t.Errorf("missing list mismatch: %+v", got)
	}
}

func TestSyncUploadsManifestDeletesStale(t *testing.T) {
	setupUploadsTest(t)

	// Pre-populate the directory + state with a file that won't be in the manifest.
	if err := uploadsRoot.WriteFile("stale.txt", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	uploadsState["stale.txt"] = shaHex("stale")

	w := postManifest(t, []uploadEntry{
		{Filename: "fresh.txt", Sha256: shaHex("fresh")},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := uploadsRoot.Stat("stale.txt"); !os.IsNotExist(err) {
		t.Errorf("stale.txt should be deleted, stat err=%v", err)
	}
	if _, present := uploadsState["stale.txt"]; present {
		t.Errorf("stale.txt should be removed from uploadsState")
	}

	var resp syncManifestResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Missing) != 1 || resp.Missing[0].Filename != "fresh.txt" {
		t.Errorf("expected only fresh.txt missing, got %+v", resp.Missing)
	}
}

func TestSyncUploadsManifestDeletesStaleSha(t *testing.T) {
	setupUploadsTest(t)

	// File present with sha A; manifest expects sha B for the same name.
	if err := uploadsRoot.WriteFile("doc.txt", []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	uploadsState["doc.txt"] = shaHex("v1")

	w := postManifest(t, []uploadEntry{
		{Filename: "doc.txt", Sha256: shaHex("v2")},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := uploadsRoot.Stat("doc.txt"); !os.IsNotExist(err) {
		t.Errorf("doc.txt should be deleted (stale sha), stat err=%v", err)
	}
	var resp syncManifestResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Missing) != 1 || resp.Missing[0].Sha256 != shaHex("v2") {
		t.Errorf("expected doc.txt with new sha in missing, got %+v", resp.Missing)
	}
}

func TestSyncUploadsManifestRejectsBadFilename(t *testing.T) {
	setupUploadsTest(t)
	w := postManifest(t, []uploadEntry{
		{Filename: "../escape", Sha256: shaHex("x")},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSyncUploadsBlobsWritesAndUpdatesState(t *testing.T) {
	setupUploadsTest(t)

	w := postBlobs(t, []uploadBlob{
		{Filename: "hello.txt", Sha256: shaHex("hi"), Contents: b64("hi")},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got, err := uploadsRoot.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("read hello.txt: %v", err)
	}
	if string(got) != "hi" {
		t.Errorf("contents: got %q want %q", got, "hi")
	}
	if uploadsState["hello.txt"] != shaHex("hi") {
		t.Errorf("uploadsState not updated: %v", uploadsState)
	}
}

func TestSyncUploadsBlobsRejectsShaMismatch(t *testing.T) {
	setupUploadsTest(t)

	w := postBlobs(t, []uploadBlob{
		{Filename: "hello.txt", Sha256: shaHex("wrong"), Contents: b64("hi")},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
	// File should not exist.
	if _, err := uploadsRoot.Stat("hello.txt"); !os.IsNotExist(err) {
		t.Errorf("hello.txt should not have been written, stat err=%v", err)
	}
	if _, present := uploadsState["hello.txt"]; present {
		t.Errorf("uploadsState should not have hello.txt: %v", uploadsState)
	}
}

func TestSyncUploadsBlobsRejectsBadBase64(t *testing.T) {
	setupUploadsTest(t)
	w := postBlobs(t, []uploadBlob{
		{Filename: "x.txt", Sha256: shaHex("x"), Contents: "not!base64!"},
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSyncUploadsBlobsCreatesSubdirs(t *testing.T) {
	setupUploadsTest(t)

	w := postBlobs(t, []uploadBlob{
		{Filename: "sub/dir/file.txt", Sha256: shaHex("nested"), Contents: b64("nested")},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	got, err := uploadsRoot.ReadFile("sub/dir/file.txt")
	if err != nil {
		t.Fatalf("read sub/dir/file.txt: %v", err)
	}
	if string(got) != "nested" {
		t.Errorf("contents: got %q", got)
	}
}

// TestSyncUploadsRoundTrip exercises the full two-step protocol end to end:
// manifest reports missing, blobs uploads them, second manifest call
// reports nothing missing.
func TestSyncUploadsRoundTrip(t *testing.T) {
	setupUploadsTest(t)

	manifest := []uploadEntry{
		{Filename: "a.txt", Sha256: shaHex("AAA")},
		{Filename: "b.txt", Sha256: shaHex("BBB")},
	}

	// Step 1: nothing on disk yet → both reported missing.
	w := postManifest(t, manifest)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest 1: status=%d", w.Code)
	}
	var resp1 syncManifestResponse
	json.Unmarshal(w.Body.Bytes(), &resp1)
	if len(resp1.Missing) != 2 {
		t.Fatalf("expected 2 missing, got %d: %+v", len(resp1.Missing), resp1.Missing)
	}

	// Step 2: send the blobs.
	blobs := []uploadBlob{
		{Filename: "a.txt", Sha256: shaHex("AAA"), Contents: b64("AAA")},
		{Filename: "b.txt", Sha256: shaHex("BBB"), Contents: b64("BBB")},
	}
	w = postBlobs(t, blobs)
	if w.Code != http.StatusOK {
		t.Fatalf("blobs: status=%d body=%s", w.Code, w.Body.String())
	}

	// Step 3: same manifest again → no missing.
	w = postManifest(t, manifest)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest 2: status=%d", w.Code)
	}
	var resp2 syncManifestResponse
	json.Unmarshal(w.Body.Bytes(), &resp2)
	if len(resp2.Missing) != 0 {
		t.Errorf("expected no missing after upload, got %+v", resp2.Missing)
	}

	// And the files actually exist with the right contents.
	for name, want := range map[string]string{"a.txt": "AAA", "b.txt": "BBB"} {
		got, err := uploadsRoot.ReadFile(name)
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

// TestSyncUploadsRejectsTraversalViaOSRoot is the kernel-level backstop:
// even if validateUploadFilename's check is bypassed, *os.Root's openat2
// would catch the escape. We verify by trying to write directly through
// the root with an escape path.
func TestSyncUploadsRejectsTraversalViaOSRoot(t *testing.T) {
	setupUploadsTest(t)
	dir := uploadsRoot.Name()
	parent := filepath.Dir(dir)

	// Try to write through *os.Root to a path that would escape.
	if err := uploadsRoot.WriteFile("../escape.txt", []byte("bad"), 0o644); err == nil {
		t.Error("expected escape write to be rejected by os.Root")
		os.Remove(filepath.Join(parent, "escape.txt"))
	}
}

package main

// Demo glue: copies any files baked into the image at demoUploadsSrc into
// /user-uploads on container startup. Lets us showcase /user-uploads without
// requiring the webapp/router to send a real `uploads` manifest.
//
// Delete this file (and its caller in main.go + the COPY in the Dockerfile +
// the demo-uploads/ directory) when the upload manifest path is wired all
// the way through and the demo is no longer needed.

import (
	"log"
	"os"
	"path/filepath"
)

const demoUploadsSrc = "/opt/demo-uploads"

// seedDemoUploads copies top-level files from demoUploadsSrc into
// /user-uploads via uploadsRoot. Subdirectories are skipped — the demo
// only needs flat files. Failures are logged and otherwise ignored: a
// missing or empty source directory is treated as "no demo files baked
// in," not an error.
//
// These files are NOT registered in uploadsState. That keeps them
// invisible to the /sync-uploads/manifest reconciliation, so a real
// upload manifest can't accidentally delete them.
func seedDemoUploads() {
	entries, err := os.ReadDir(demoUploadsSrc)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("seed demo uploads: read %s: %v", demoUploadsSrc, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(demoUploadsSrc, e.Name()))
		if err != nil {
			log.Printf("seed demo uploads: read %s: %v", e.Name(), err)
			continue
		}
		// 0o644 → owner (uid 1000) rw, others (incl. bash uid 1001) read-only,
		// matching the perms set by the real /sync-uploads/blobs path.
		if err := uploadsRoot.WriteFile(e.Name(), data, 0o644); err != nil {
			log.Printf("seed demo uploads: write %s: %v", e.Name(), err)
			continue
		}
		log.Printf("seed demo uploads: wrote %s (%d bytes)", e.Name(), len(data))
	}
}

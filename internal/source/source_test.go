package source

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareDirectory(t *testing.T) {
	dir := t.TempDir()
	prepared, err := Prepare(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Cleanup()
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Path != want {
		t.Fatalf("path=%q want=%q", prepared.Path, want)
	}
}

func TestPrepareZIPAndUnwrapRoot(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "repo.zip")
	writeZIP(t, archive, map[string]string{"repo/main.go": "package main\n", "repo/nested/README.md": "nested\n"})
	prepared, err := Prepare(archive)
	if err != nil {
		t.Fatal(err)
	}
	root := prepared.Path
	if _, err := os.Stat(filepath.Join(root, "main.go")); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("temporary source was not removed: %v", err)
	}
}

func TestPrepareZIPRejectsTraversal(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.zip")
	writeZIP(t, archive, map[string]string{"../outside": "bad"})
	if _, err := Prepare(archive); err == nil {
		t.Fatal("expected unsafe ZIP entry to be rejected")
	}
}

func writeZIP(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range files {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

package source

import (
	"archive/zip"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestAddArchiveSizeRejectsLimitAndOverflow(t *testing.T) {
	if _, ok := addArchiveSize(maxArchiveBytes, 1, maxArchiveBytes); ok {
		t.Fatal("size above extraction limit accepted")
	}
	if _, ok := addArchiveSize(1, math.MaxUint64, maxArchiveBytes); ok {
		t.Fatal("overflowing size accepted")
	}
	if got, ok := addArchiveSize(10, 20, maxArchiveBytes); !ok || got != 30 {
		t.Fatalf("valid size rejected: got=%d ok=%v", got, ok)
	}
}

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

func TestPrepareZIPPreservesHiddenRepositoryDirectories(t *testing.T) {
	for _, prefix := range []string{"", "repository/"} {
		t.Run(prefix, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "snapshot.zip")
			name := ".github/workflows/check.yml"
			writeZIP(t, archive, map[string]string{prefix + name: "name: check\n"})
			prepared, err := Prepare(archive)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Cleanup()
			if _, err := os.Stat(filepath.Join(prepared.Path, filepath.FromSlash(name))); err != nil {
				t.Fatalf("repository-relative workflow was lost: %v", err)
			}
		})
	}
}

func TestValidateZIPHonorsConfiguredLimits(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "limited.zip")
	writeZIP(t, archive, map[string]string{"one.txt": "12345", "two.txt": "67890"})
	if err := ValidateZIP(archive, Limits{MaxFiles: 1, MaxExpandedBytes: 100}); err == nil {
		t.Fatal("file count above configured limit accepted")
	}
	if err := ValidateZIP(archive, Limits{MaxFiles: 2, MaxExpandedBytes: 9}); err == nil {
		t.Fatal("expanded size above configured limit accepted")
	}
	if err := ValidateZIP(archive, Limits{MaxFiles: 2, MaxExpandedBytes: 10}); err != nil {
		t.Fatalf("archive at configured limits rejected: %v", err)
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

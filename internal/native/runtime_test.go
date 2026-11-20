package native

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

func TestBundledRuntimeRepairsCorruptCache(t *testing.T) {
	if !Available() {
		t.Skip("requires bundled build")
	}
	cache := t.TempDir()
	binary, err := Resolve(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	repaired, err := Resolve(cache)
	if err != nil || repaired != binary {
		t.Fatalf("repair failed: %s %v", repaired, err)
	}
	data, err := os.ReadFile(binary)
	if err != nil || bytes.Equal(data, []byte("tampered")) {
		t.Fatal("corrupt executable survived")
	}
}

func TestRuntimeUnpackRejectsTraversalAndResolvesLibraries(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "dir/../../escape", "C:/escape"} {
		if safePath(name) {
			t.Fatalf("unsafe path accepted: %s", name)
		}
	}
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "lib/libllama.so.1", Mode: 0755, Size: 3})
	_, _ = tw.Write([]byte("lib"))
	_ = tw.WriteHeader(&tar.Header{Name: "lib/libllama.so", Linkname: "libllama.so.1", Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	_ = gz.Close()
	files, err := Unpack(buffer.Bytes(), "runtime.tar.gz")
	if err != nil || string(files["lib/libllama.so"]) != "lib" {
		t.Fatalf("library resolution: %v %v", files, err)
	}
	if Verify([]byte("tampered"), Assets["linux/amd64"]) == nil {
		t.Fatal("tampered archive accepted")
	}
}

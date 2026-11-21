// Package native carries the pinned llama.cpp distribution in release binaries.
package native

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const Version = "b12359"

type Asset struct{ Name, SHA256 string }

var Assets = map[string]Asset{
	"darwin/arm64":  {"llama-b12359-bin-macos-arm64.tar.gz", "82b00abc740160e1b9980e6cc79c117345fa34af058c80e6c0a69aa8ddccde75"},
	"darwin/amd64":  {"llama-b12359-bin-macos-x64.tar.gz", "25320d529077ef5a3d16e7b5da26438f221d88c8c0930a32b0c79457f5eede56"},
	"linux/amd64":   {"llama-b12359-bin-ubuntu-x64.tar.gz", "0bc1f091e8916102b6d8f2cf944233a620e90a0f856c72d0ce41150c65c2e72e"},
	"linux/arm64":   {"llama-b12359-bin-ubuntu-arm64.tar.gz", "dc7aa17a67884619b7223870aca9fd6addbc01717713b04a714add1c31137359"},
	"windows/amd64": {"llama-b12359-bin-win-cpu-x64.zip", "837c1655e87df3b66989f4be33a792a1399c785bf259038dc75c900096683e69"},
	"windows/arm64": {"llama-b12359-bin-win-cpu-arm64.zip", "d27564c754478d2832789dfcebfc5ace018e36a224c41d810b7cbc1ba8243ec0"},
}

var extractMu sync.Mutex

func Available() bool { _, err := payload.ReadFile("payload/runtime.archive"); return err == nil }

func Resolve(cache string) (string, error) {
	data, err := payload.ReadFile("payload/runtime.archive")
	if err != nil {
		return "", nil
	}
	asset := Assets[runtime.GOOS+"/"+runtime.GOARCH]
	if err := Verify(data, asset); err != nil {
		return "", err
	}
	extractMu.Lock()
	defer extractMu.Unlock()
	files, err := Unpack(data, asset.Name)
	if err != nil {
		return "", err
	}
	base := filepath.Join(cache, "embedded-"+Version+"-"+asset.SHA256[:16])
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	binary := "llama-server"
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	var executable string
	for name, content := range files {
		path := filepath.Join(base, filepath.FromSlash(name))
		if filepath.Base(path) == binary {
			executable = path
		}
		current, err := os.ReadFile(path)
		if err == nil && bytes.Equal(current, content) {
			if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0o100 != 0) {
				continue
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".runtime-*")
		if err != nil {
			return "", err
		}
		tmp := file.Name()
		_, writeErr := file.Write(content)
		modeErr := file.Chmod(0o700)
		closeErr := file.Close()
		if writeErr != nil || modeErr != nil || closeErr != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("write embedded runtime: %v %v %v", writeErr, modeErr, closeErr)
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return "", err
		}
	}
	if executable == "" {
		return "", fmt.Errorf("embedded runtime missing %s", binary)
	}
	return executable, nil
}

func Verify(data []byte, asset Asset) error {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != asset.SHA256 {
		return fmt.Errorf("native runtime digest mismatch or incorrect build target")
	}
	return nil
}

// Unpack materializes library symlinks as regular files; no archive path can escape.
func Unpack(data []byte, name string) (map[string][]byte, error) {
	files := map[string][]byte{}
	links := map[string]string{}
	var total int64
	add := func(name string, reader io.Reader) error {
		name = strings.TrimPrefix(name, "./")
		if !safePath(name) {
			return fmt.Errorf("unsafe runtime path %q", name)
		}
		body, err := io.ReadAll(io.LimitReader(reader, (1<<30)-total+1))
		total += int64(len(body))
		if err != nil || total > 1<<30 {
			return fmt.Errorf("runtime expanded size exceeds limit or read failed: %v", err)
		}
		files[name] = body
		return nil
	}
	if strings.HasSuffix(name, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, file := range zr.File {
			if file.FileInfo().IsDir() {
				continue
			}
			r, err := file.Open()
			if err != nil {
				return nil, err
			}
			err = add(file.Name, r)
			r.Close()
			if err != nil {
				return nil, err
			}
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			switch header.Typeflag {
			case tar.TypeReg:
				if err := add(header.Name, tr); err != nil {
					return nil, err
				}
			case tar.TypeSymlink, tar.TypeLink:
				target := header.Linkname
				if header.Typeflag == tar.TypeSymlink {
					target = filepath.ToSlash(filepath.Join(filepath.Dir(header.Name), target))
				}
				if !safePath(header.Name) || !safePath(target) {
					return nil, fmt.Errorf("unsafe runtime library link")
				}
				links[header.Name] = target
			}
		}
	}
	for len(links) > 0 {
		progress := false
		for name, target := range links {
			if body, ok := files[target]; ok {
				files[name] = body
				delete(links, name)
				progress = true
			}
		}
		if !progress {
			return nil, fmt.Errorf("unresolved runtime library links")
		}
	}
	return files, nil
}

func safePath(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return false
		}
	}
	return true
}

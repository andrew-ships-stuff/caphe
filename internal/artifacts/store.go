package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

func (s *Store) Put(data []byte) (string, string, error) {
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	dir := filepath.Join(s.root, "sha256", digest[7:9])
	path := filepath.Join(dir, digest[7:])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create artifact directory: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return digest, path, nil
	}
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return "", "", err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(name, path); err != nil {
		return "", "", err
	}
	return digest, path, nil
}

func (s *Store) Get(digest string) ([]byte, error) {
	if len(digest) != 71 || digest[:7] != "sha256:" {
		return nil, fmt.Errorf("invalid digest")
	}
	return os.ReadFile(filepath.Join(s.root, "sha256", digest[7:9], digest[7:]))
}

package source

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxArchiveFiles = 100_000
	maxArchiveBytes = 4 << 30
)

type Limits struct {
	MaxFiles         int
	MaxExpandedBytes uint64
}

func DefaultLimits() Limits {
	return Limits{MaxFiles: maxArchiveFiles, MaxExpandedBytes: maxArchiveBytes}
}

type Prepared struct {
	Path    string
	Display string
	cleanup func() error
}

func (p Prepared) Cleanup() error {
	if p.cleanup == nil {
		return nil
	}
	return p.cleanup()
}

func Prepare(target string) (Prepared, error) {
	return PrepareWithLimits(target, DefaultLimits())
}

func PrepareWithLimits(target string, limits Limits) (Prepared, error) {
	limits = normalizeLimits(limits)
	if target == "" {
		target = "."
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return Prepared{}, fmt.Errorf("resolve target: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Prepared{}, fmt.Errorf("resolve target: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return Prepared{}, fmt.Errorf("inspect target: %w", err)
	}
	if info.IsDir() {
		return Prepared{Path: resolved, Display: target}, nil
	}
	if !strings.EqualFold(filepath.Ext(resolved), ".zip") {
		return Prepared{}, fmt.Errorf("target must be a directory or .zip archive: %s", target)
	}
	return extractZIP(resolved, target, limits)
}

func ValidateZIP(archivePath string, limits Limits) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open ZIP target: %w", err)
	}
	defer reader.Close()
	return validateZIPFiles(reader.File, normalizeLimits(limits))
}

func normalizeLimits(limits Limits) Limits {
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = maxArchiveFiles
	}
	if limits.MaxExpandedBytes == 0 {
		limits.MaxExpandedBytes = maxArchiveBytes
	}
	return limits
}

func validateZIPFiles(files []*zip.File, limits Limits) error {
	if len(files) > limits.MaxFiles {
		return fmt.Errorf("ZIP target contains too many entries: %d", len(files))
	}
	var size uint64
	for _, file := range files {
		var ok bool
		size, ok = addArchiveSize(size, file.UncompressedSize64, limits.MaxExpandedBytes)
		if !ok {
			return fmt.Errorf("ZIP target exceeds %d byte extraction limit", limits.MaxExpandedBytes)
		}
		if !filepath.IsLocal(file.Name) || strings.Contains(file.Name, `\`) || file.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ZIP target contains unsafe entry %q", file.Name)
		}
	}
	return nil
}

func extractZIP(archivePath, display string, limits Limits) (prepared Prepared, err error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return Prepared{}, fmt.Errorf("open ZIP target: %w", err)
	}
	defer reader.Close()
	if err := validateZIPFiles(reader.File, limits); err != nil {
		return Prepared{}, err
	}
	root, err := os.MkdirTemp("", "caphe-source-")
	if err != nil {
		return Prepared{}, fmt.Errorf("create ZIP workspace: %w", err)
	}
	prepared = Prepared{Path: root, Display: display, cleanup: func() error { return os.RemoveAll(root) }}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()
	for _, file := range reader.File {
		path := filepath.Join(root, filepath.FromSlash(file.Name))
		if file.FileInfo().IsDir() {
			if err = os.MkdirAll(path, 0o700); err != nil {
				return Prepared{}, fmt.Errorf("create ZIP directory: %w", err)
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return Prepared{}, fmt.Errorf("create ZIP parent: %w", err)
		}
		if err = extractFile(file, path); err != nil {
			return Prepared{}, err
		}
	}
	prepared.Path = unwrapSingleDirectory(root)
	return prepared, nil
}

func addArchiveSize(total, next, limit uint64) (uint64, bool) {
	if total > limit || next > limit-total {
		return 0, false
	}
	return total + next, true
}

func extractFile(file *zip.File, path string) error {
	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("open ZIP entry %q: %w", file.Name, err)
	}
	defer src.Close()
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create ZIP entry %q: %w", file.Name, err)
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return fmt.Errorf("extract ZIP entry %q: %w", file.Name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close ZIP entry %q: %w", file.Name, closeErr)
	}
	return nil
}

func unwrapSingleDirectory(root string) string {
	entries, err := os.ReadDir(root)
	if err == nil && len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(root, entries[0].Name())
	}
	return root
}

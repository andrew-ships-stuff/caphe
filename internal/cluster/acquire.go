package cluster

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/andrew-ships-stuff/caphe/internal/source"
)

func acquireGit(ctx context.Context, spec Source, limits source.Limits, maxArchiveBytes int64) (string, func(), error) {
	root, err := os.MkdirTemp("", "caphe-git-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	repo := filepath.Join(root, "repository")
	if err := os.Mkdir(repo, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C"}
	commands := [][]string{
		{"init", "--quiet"},
		{"remote", "add", "origin", spec.GitURL},
		{"-c", "protocol.file.allow=never", "fetch", "--quiet", "--depth=1", "--no-tags", "origin", spec.CommitSHA},
		{"checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, args := range commands {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = repo
		cmd.Env = env
		cmd.Stdin = nil
		output, err := cmd.CombinedOutput()
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("Git acquisition failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = repo
	cmd.Env = env
	output, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != spec.CommitSHA {
		cleanup()
		return "", nil, fmt.Errorf("Git server did not resolve the requested immutable commit")
	}
	archive := filepath.Join(root, "source.zip")
	if err := archiveDirectory(repo, archive, limits, maxArchiveBytes); err != nil {
		cleanup()
		return "", nil, err
	}
	return archive, cleanup, nil
}

func archiveDirectory(root, destination string, limits source.Limits, maxArchiveBytes int64) error {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(file)
	count := 0
	var expanded uint64
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "." || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Git source contains unsupported non-regular file %q", rel)
		}
		count++
		if count > limits.MaxFiles || info.Size() < 0 || expanded+uint64(info.Size()) < expanded || expanded+uint64(info.Size()) > limits.MaxExpandedBytes {
			return fmt.Errorf("Git source exceeds archive limits")
		}
		expanded += uint64(info.Size())
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		header.Method = zip.Deflate
		header.SetMode(0o600)
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, src)
		closeErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	closeZipErr := zw.Close()
	closeFileErr := file.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeZipErr != nil {
		return closeZipErr
	}
	if closeFileErr != nil {
		return closeFileErr
	}
	info, err := os.Stat(destination)
	if err != nil {
		return err
	}
	if info.Size() > maxArchiveBytes {
		return fmt.Errorf("Git snapshot exceeds compressed archive limit")
	}
	return source.ValidateZIP(destination, limits)
}

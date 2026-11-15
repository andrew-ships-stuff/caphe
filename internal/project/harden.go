package project

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Result struct {
	Root     string   `json:"root"`
	Created  []string `json:"created"`
	Existing []string `json:"existing"`
}

var recommendedFiles = map[string]string{
	".poutine.yml": "disableVersionCheck: true\nignoreForks: true\nskip: []\n",
	".github/dependabot.yml": `version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule: {interval: weekly}
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    directory: /
    schedule: {interval: weekly}
    open-pull-requests-limit: 5
  - package-ecosystem: docker
    directory: /
    schedule: {interval: weekly}
    open-pull-requests-limit: 5
`,
}

func Apply(root string) (Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Result{}, fmt.Errorf("inspect project root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return Result{}, fmt.Errorf("inspect project root: %w", err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("project root is not a directory")
	}
	r := Result{Root: resolved}
	keys := make([]string, 0, len(recommendedFiles))
	for key := range recommendedFiles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, rel := range keys {
		content := recommendedFiles[rel]
		path := filepath.Join(resolved, filepath.FromSlash(rel))
		if _, err := os.Lstat(path); err == nil {
			r.Existing = append(r.Existing, rel)
			continue
		} else if !os.IsNotExist(err) {
			return r, err
		}
		if err := ensureSafeParent(resolved, filepath.Dir(path)); err != nil {
			return r, err
		}
		if err := writeExclusive(path, []byte(content)); err != nil {
			return r, err
		}
		r.Created = append(r.Created, rel)
	}
	return r, nil
}

func ensureSafeParent(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || rel == ".." || filepath.IsAbs(rel) {
		return fmt.Errorf("configuration path escapes project root")
	}
	current := root
	if rel == "." {
		return nil
	}
	for _, part := range splitPath(rel) {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
			continue
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("refusing unsafe configuration parent %s", current)
		}
	}
	return nil
}

func splitPath(path string) []string {
	var parts []string
	for path != "." && path != "" {
		dir, file := filepath.Split(path)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		path = filepath.Clean(dir)
		if path == string(filepath.Separator) {
			break
		}
	}
	return parts
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

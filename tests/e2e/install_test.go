package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMakeInstallIncludesManagedTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Makefile installation requires POSIX tools")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make unavailable")
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "installer failure"}[fail], func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range map[string]string{
				"Makefile":                 string(makefile),
				"scripts/install-tools.sh": "#!/bin/sh\nprintf '%s\\n' \"$@\" > installer-args\n" + map[bool]string{false: "", true: "exit 1\n"}[fail],
				"fake-bin/go":              "#!/bin/sh\nmkdir -p bin\nprintf 'fake caphe' > bin/caphe\n",
			} {
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cache := filepath.Join(dir, "cache with spaces")
			cmd := exec.Command("make", "install", "TOOLS=syft,grype", "XDG_CACHE_HOME="+cache)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "fake-bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if (err != nil) != fail {
				t.Fatalf("make install: %v\n%s", err, out)
			}
			args, err := os.ReadFile(filepath.Join(dir, "installer-args"))
			if err != nil {
				t.Fatal(err)
			}
			want := "--bin-dir\n" + filepath.Join(cache, "caphe", "bin") + "\n--tools\nsyft,grype\n"
			if string(args) != want {
				t.Fatalf("installer arguments = %q, want %q", args, want)
			}
			if !fail {
				for _, path := range []string{"bin/caphe", "libexec/install-tools.sh"} {
					if _, err := os.Stat(filepath.Join(cache, "caphe", path)); err != nil {
						t.Fatal(err)
					}
				}
			} else if strings.Contains(string(out), "Installed to") {
				t.Fatal("failed tool installation reported success")
			}
		})
	}
}

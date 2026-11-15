package adapters

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

var ErrOutputLimit = errors.New("scanner output exceeded limit")

type limitedBuffer struct {
	b        bytes.Buffer
	n        int64
	limit    int64
	exceeded bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := w.limit - w.n
	if remaining > 0 {
		q := p
		if int64(len(q)) > remaining {
			q = q[:remaining]
		}
		n, _ := w.b.Write(q)
		w.n += int64(n)
	}
	if int64(original) > remaining {
		w.exceeded = true
	}
	return original, nil
}

func RunCommand(ctx context.Context, dir, executable string, args []string, maxOutput int64) ([]byte, []byte, int, error) {
	if maxOutput <= 0 {
		maxOutput = 64 << 20
	}
	stdout := &limitedBuffer{limit: maxOutput}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if stdout.exceeded {
		return stdout.b.Bytes(), stderr.b.Bytes(), code, ErrOutputLimit
	}
	if err != nil {
		return stdout.b.Bytes(), stderr.b.Bytes(), code, fmt.Errorf("scanner process: %w: %s", err, string(stderr.b.Bytes()))
	}
	return stdout.b.Bytes(), stderr.b.Bytes(), code, nil
}

var _ io.Writer = (*limitedBuffer)(nil)

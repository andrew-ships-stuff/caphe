// Build-time asset preparation, run on the host before cross-compiling Caphe.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/andrew-ships-stuff/caphe/internal/native"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

func main() {
	target := flag.String("target", runtime.GOOS+"/"+runtime.GOARCH, "release OS/architecture")
	output := flag.String("output", "internal/native/payload/runtime.archive", "generated archive destination")
	flag.Parse()
	if err := run(*target, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(target, output string) error {
	asset, ok := native.Assets[target]
	if !ok {
		return fmt.Errorf("unsupported runtime target %s", target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://github.com/ggml-org/llama.cpp/releases/download/"+native.Version+"/"+asset.Name, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("runtime download: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return err
	}
	if err := native.Verify(data, asset); err != nil {
		return err
	}
	if _, err := native.Unpack(data, asset.Name); err != nil {
		return err
	}
	return os.WriteFile(output, data, 0o600)
}

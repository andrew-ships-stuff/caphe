package inference

import (
	"slices"
	"testing"
)

func TestCPUOnlyRuntimeArguments(t *testing.T) {
	args := serverArgs(ServerOptions{ModelPath: "model.gguf", Threads: 8, Parallel: 2, ContextTokens: 4096})
	for flag, want := range map[string]string{"--device": "none", "--n-gpu-layers": "0", "--threads": "8", "--threads-batch": "8", "--parallel": "2", "--ctx-size": "8192"} {
		i := slices.Index(args, flag)
		if i < 0 || args[i+1] != want {
			t.Fatalf("%s: %v", flag, args)
		}
	}
}

package inference

import (
	"fmt"
	"github.com/shirou/gopsutil/v4/cpu"
	"runtime"
)

func CPUThreads() int {
	n := runtime.GOMAXPROCS(0)
	if physical, err := cpu.Counts(false); err == nil && physical > 0 && physical < n {
		n = physical
	}
	return max(1, n)
}

func serverArgs(options ServerOptions) []string {
	threads := options.Threads
	if threads <= 0 {
		threads = CPUThreads()
	}
	parallel := max(1, options.Parallel)
	context := options.ContextTokens
	if context <= 0 {
		context = 4096
	}
	return []string{"-m", options.ModelPath, "--host", "127.0.0.1", "--device", "none", "--n-gpu-layers", "0", "--no-kv-offload", "--threads", fmt.Sprint(threads), "--threads-batch", fmt.Sprint(threads), "--parallel", fmt.Sprint(parallel), "--ctx-size", fmt.Sprint(context * parallel), "--cont-batching"}
}

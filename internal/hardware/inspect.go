package hardware

import (
	"context"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

type Inspection struct {
	OS                    string   `json:"os"`
	Architecture          string   `json:"architecture"`
	LogicalCores          int      `json:"logicalCores"`
	PhysicalCores         int      `json:"physicalCores,omitempty"`
	TotalMemoryBytes      uint64   `json:"totalMemoryBytes"`
	AvailableMemoryBytes  uint64   `json:"availableMemoryBytes"`
	DiskFreeBytes         uint64   `json:"diskFreeBytes"`
	CPUFeatures           []string `json:"cpuFeatures,omitempty"`
	Virtualization        string   `json:"virtualization,omitempty"`
	Containerized         bool     `json:"containerized"`
	KubernetesCPUlimit    string   `json:"kubernetesCpuLimit,omitempty"`
	KubernetesMemoryLimit string   `json:"kubernetesMemoryLimit,omitempty"`
}

func Inspect(ctx context.Context, path string) (Inspection, error) {
	if _, err := os.Stat(path); err != nil {
		path = "."
	}
	i := Inspection{OS: runtime.GOOS, Architecture: runtime.GOARCH, LogicalCores: runtime.NumCPU()}
	if n, err := cpu.Counts(false); err == nil {
		i.PhysicalCores = n
	}
	if v, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		i.TotalMemoryBytes = v.Total
		i.AvailableMemoryBytes = v.Available
	}
	if d, err := disk.UsageWithContext(ctx, path); err == nil {
		i.DiskFreeBytes = d.Free
	}
	if rows, err := cpu.InfoWithContext(ctx); err == nil {
		set := map[string]bool{}
		for _, r := range rows {
			for _, f := range r.Flags {
				set[f] = true
			}
		}
		for f := range set {
			i.CPUFeatures = append(i.CPUFeatures, f)
		}
		sort.Strings(i.CPUFeatures)
	}
	if h, err := host.InfoWithContext(ctx); err == nil {
		i.Virtualization = strings.TrimSpace(h.VirtualizationSystem)
		i.Containerized = h.VirtualizationRole == "guest" && (h.VirtualizationSystem == "docker" || h.VirtualizationSystem == "lxc" || h.VirtualizationSystem == "podman")
	}
	i.KubernetesCPUlimit = os.Getenv("CPU_LIMIT")
	i.KubernetesMemoryLimit = os.Getenv("MEMORY_LIMIT")
	return i, nil
}

type Model struct {
	Name           string `json:"name"`
	Tier           string `json:"tier"`
	Parameters     string `json:"parameters"`
	Quantization   string `json:"quantization"`
	EstimatedBytes uint64 `json:"estimatedBytes"`
	Status         string `json:"status"`
}
type Recommendation struct {
	Mode               string `json:"mode"`
	Model              *Model `json:"model,omitempty"`
	Reason             string `json:"reason"`
	SafetyReserveBytes uint64 `json:"safetyReserveBytes"`
}

func SupportedModels() []Model {
	return []Model{{Name: "qwen2.5-coder-0.5b-instruct-q4_k_m", Tier: "tiny", Parameters: "0.5B", Quantization: "Q4_K_M", EstimatedBytes: 1_200_000_000, Status: "candidate-unvalidated"}, {Name: "qwen2.5-coder-1.5b-instruct-q4_k_m", Tier: "small", Parameters: "1.5B", Quantization: "Q4_K_M", EstimatedBytes: 2_400_000_000, Status: "candidate-unvalidated"}, {Name: "qwen2.5-coder-3b-instruct-q4_k_m", Tier: "medium", Parameters: "3B", Quantization: "Q4_K_M", EstimatedBytes: 4_800_000_000, Status: "candidate-unvalidated"}}
}
func Recommend(i Inspection) Recommendation {
	reserve := i.TotalMemoryBytes / 4
	if reserve < 1<<30 {
		reserve = 1 << 30
	}
	usable := uint64(0)
	if i.AvailableMemoryBytes > reserve {
		usable = i.AvailableMemoryBytes - reserve
	}
	models := SupportedModels()
	var chosen *Model
	for idx := range models {
		if models[idx].EstimatedBytes <= usable {
			m := models[idx]
			chosen = &m
		}
	}
	if chosen == nil {
		return Recommendation{Mode: "deterministic", Reason: "available memory after safety reserve is insufficient for a supported candidate", SafetyReserveBytes: reserve}
	}
	return Recommendation{Mode: "cpu-assisted", Model: chosen, Reason: "largest candidate fitting current available memory and safety reserve; task accuracy is not yet validated", SafetyReserveBytes: reserve}
}

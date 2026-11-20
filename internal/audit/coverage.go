package audit

import (
	"strings"

	capheruntime "github.com/andrew-ships-stuff/caphe/internal/runtime"
)

type Coverage struct {
	Complete    bool     `json:"complete"`
	Succeeded   []string `json:"succeeded"`
	Unavailable []string `json:"unavailable"`
	Failed      []string `json:"failed"`
}

func scanCoverage(tasks []capheruntime.TaskResult) Coverage {
	c := Coverage{Succeeded: []string{}, Unavailable: []string{}, Failed: []string{}}
	for _, task := range tasks {
		if !strings.HasPrefix(task.Uses, "scanner.") {
			continue
		}
		switch task.Status {
		case capheruntime.StatusSucceeded:
			c.Succeeded = append(c.Succeeded, task.ID)
		case capheruntime.StatusSkipped:
			c.Unavailable = append(c.Unavailable, task.ID)
		default:
			c.Failed = append(c.Failed, task.ID)
		}
	}
	c.Complete = len(c.Succeeded) > 0 && len(c.Unavailable) == 0 && len(c.Failed) == 0
	return c
}

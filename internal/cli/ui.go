package cli

import (
	"github.com/andrew-ships-stuff/caphe/internal/workbench"
	"github.com/spf13/cobra"
)

func (a *app) uiCmd() *cobra.Command {
	var listen, endpoint string
	cmd := &cobra.Command{Use: "ui", Short: "Open the security engineering workbench server", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return workbench.Serve(cmd.Context(), listen, endpoint, a.stdout)
	}}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:3000", "workbench HTTP listen address")
	cmd.Flags().StringVar(&endpoint, "api", "http://127.0.0.1:8787", "cluster API origin (fixed server-side proxy target)")
	return cmd
}

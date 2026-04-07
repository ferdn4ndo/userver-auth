package commands

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// HealthProbeCommand exits 0 when /healthz responds OK on the configured listen port (no full app graph).
func HealthProbeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "health:probe",
		Short: "GET /healthz on localhost (for container health checks)",
		RunE: func(cmd *cobra.Command, args []string) error {
			port := "5000"
			for _, k := range []string{"APP_PORT", "PORT", "FLASK_PORT"} {
				if v := strings.TrimSpace(os.Getenv(k)); v != "" {
					port = v
					break
				}
			}
			url := "http://127.0.0.1:" + port + "/healthz"
			client := &http.Client{Timeout: 4 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("healthz: status %d", resp.StatusCode)
			}
			return nil
		},
	}
}

package osv

import (
	"os/exec"

	"github.com/rs/zerolog/log"
)

func Scan(dir string) (isVulnerable bool, report string, err error) {
	isVulnerable = false

	log.Info().Msg("Starting osv-scanner...")
	cmd := exec.Command("osv-scanner", "-r", "--verbosity", "error", "--format", "table", dir)

	if out, err := cmd.Output(); err != nil {
		if exitErr := err.(*exec.ExitError); exitErr != nil && exitErr.ExitCode() == 1 {
			isVulnerable = true
			report = string(out)
			err = nil // Exit code 1 is not a runtime error, it means vulnerabilities were found, so we ignore the exit code
		}
	}

	return
}

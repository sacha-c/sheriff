package osv

import (
	"log"
	"os/exec"
)

func Scan(dir string) (isVulnerable bool, report string, err error) {
	isVulnerable = false

	log.Default().Print("Starting osv-scanner...")
	cmd := exec.Command("osv-scanner", "-r", "--verbosity", "error", "--format", "markdown", dir)

	if out, err := cmd.Output(); err != nil {
		isVulnerable = true
		if exitErr := err.(*exec.ExitError); exitErr != nil && exitErr.ExitCode() == 1 {
			report = string(out)
			err = nil // Exit code 1 is not a runtime error, it means vulnerabilities were found, so we ignore the exit code
		}
	}

	return
}

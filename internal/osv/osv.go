package osv

import (
	"encoding/json"
	"os/exec"

	"github.com/rs/zerolog/log"
)

type ReferenceKind string

const (
	AdvisoryKind ReferenceKind = "ADVISORY"
	WebKind      ReferenceKind = "WEB"
	PackageKind  ReferenceKind = "PACKAGE"
)

type SeverityScoreKind string

const (
	Critical SeverityScoreKind = "CRITICAL"
	High     SeverityScoreKind = "HIGH"
	Moderate SeverityScoreKind = "MODERATE"
	Low      SeverityScoreKind = "LOW"
	Unknown  SeverityScoreKind = "UNKNOWN"
)

type Source struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type Reference struct {
	Type ReferenceKind `json:"type"`
	Url  string        `json:"url"`
}

type DatabaseSpecific struct {
	Severity SeverityScoreKind `json:"severity"`
}

type Vulnerability struct {
	Id               string           `json:"id"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Detail           string           `json:"detail"`
	Version          string           `json:"schema_version"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

type Group struct {
	Ids         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type Package struct {
	PackageInfo     PackageInfo     `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Groups          []Group         `json:"groups"`
}

type Result struct {
	Source   Source    `json:"source"`
	Packages []Package `json:"packages"`
}

type Report struct {
	Results []Result `json:"results"`
}

func Scan(dir string) (report *Report, err error) {
	log.Info().Msg("Starting osv-scanner...")
	cmd := exec.Command("osv-scanner", "-r", "--verbosity", "error", "--format", "json", dir)

	out, err := cmd.Output()
	if err != nil {
		if exitErr := err.(*exec.ExitError); exitErr != nil && exitErr.ExitCode() == 1 {
			err = readOSVJson(out, &report)
			if err != nil {
				return
			}
		}

		return
	}

	return
}

func readOSVJson(data []byte, report **Report) (err error) {
	err = json.Unmarshal(data, report)
	if err != nil {
		return
	}

	return
}

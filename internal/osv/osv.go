package osv

import (
	"encoding/json"
	"securityscanner/internal/shell"

	"github.com/rs/zerolog/log"
)

type ReferenceKind string

const (
	AdvisoryKind ReferenceKind = "ADVISORY"
	WebKind      ReferenceKind = "WEB"
	PackageKind  ReferenceKind = "PACKAGE"
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
	Severity string `json:"severity"`
}

type Event struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type Range struct {
	Events []Event `json:"events"`
}

type Affected struct {
	Ranges []Range `json:"ranges"`
}

type Vulnerability struct {
	Id               string           `json:"id"`
	Aliases          []string         `json:"aliases"`
	Summary          string           `json:"summary"`
	Detail           string           `json:"detail"`
	Version          string           `json:"schema_version"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
	Affected         []Affected       `json:"affected"`
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

type IService interface {
	Scan(dir string) (*Report, error)
}

type service struct{}

func NewService() IService {
	return &service{}
}

// Scan runs osv-scanner on the given directory
// and returns a Report struct with the results
func (s *service) Scan(dir string) (*Report, error) {
	var report *Report

	cmdOut, err := shell.ShellCommandRunner.Run("osv-scanner", "-r", "--verbosity", "error", "--format", "json", dir)

	//Handle exit codes according to https://google.github.io/osv-scanner/output/#return-codes
	if cmdOut.ExitCode == 0 && err == nil {
		// Successful run of osv-scanner, no report because no vulnerabilities found
		log.Debug().Msgf("osv-scanner did not find vulnerabilities; returned exit code %v", cmdOut.ExitCode)
		return nil, nil
	} else if cmdOut.ExitCode > 1 || cmdOut.ExitCode == -1 {
		// Failed to run osv-scanner at all, or it returned an error
		log.Debug().Msgf("osv-scanner failed to run; returned exit code %v", cmdOut.ExitCode)
		return nil, err
	}
	// Error code 1, osv-scanner ran successfully and found vulnerabilities
	log.Debug().Msg("osv-scanner ran successfully; found vulnerabilities")
	report, err = readOSVJson(cmdOut.Output)
	if err != nil {
		return report, err
	}

	return report, nil
}

// readOSVJson reads the JSON output from osv-scanner
// and returns a Report struct with the results
func readOSVJson(data []byte) (report *Report, err error) {
	err = json.Unmarshal(data, &report)
	return
}

package scanner

import (
	"encoding/json"
	"path/filepath"
	"sheriff/internal/shell"
	"strconv"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

type osvReferenceKind string

const (
	AdvisoryKind osvReferenceKind = "ADVISORY"
	WebKind      osvReferenceKind = "WEB"
	PackageKind  osvReferenceKind = "PACKAGE"
)

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvReference struct {
	Type osvReferenceKind `json:"type"`
	Url  string           `json:"url"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvRange struct {
	Events []osvEvent `json:"events"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvVulnerability struct {
	Id               string              `json:"id"`
	Aliases          []string            `json:"aliases"`
	Summary          string              `json:"summary"`
	Detail           string              `json:"detail"`
	Version          string              `json:"schema_version"`
	References       []osvReference      `json:"references"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
	Affected         []osvAffected       `json:"affected"`
}

type osvGroup struct {
	Ids         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

type osvPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvPackage struct {
	PackageInfo     osvPackageInfo     `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

// Vulnerability report as returned by osv-scanner
type OsvReport struct {
	Results []osvResult `json:"results"`
}

// osvScanner is a concrete implementation of the VulnScanner interface
// that uses Google's osv-scanner to scan for vulnerabilities in a project directory.
type osvScanner struct{}

func NewOsvScanner() VulnScanner[OsvReport] {
	return &osvScanner{}
}

func (s *osvScanner) Scan(dir string) (*OsvReport, error) {
	var report *OsvReport

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

func (s *osvScanner) GenerateReport(p *gogitlab.Project, r *OsvReport) Report {
	if r == nil {
		return Report{
			Project:         p,
			IsVulnerable:    false,
			Vulnerabilities: []Vulnerability{},
		}
	}

	var vs []Vulnerability
	for _, p := range r.Results {
		for _, pkg := range p.Packages {
			for _, v := range pkg.Vulnerabilities {
				packageRef := pie.FirstOr(pie.Filter(v.References, func(ref osvReference) bool { return ref.Type == PackageKind }), osvReference{})
				source := filepath.Base(p.Source.Path)
				sevIdx := pie.FindFirstUsing(pkg.Groups, func(g osvGroup) bool { return pie.Contains(g.Ids, v.Id) || pie.Contains(g.Aliases, v.Id) })
				var severity string
				if sevIdx != -1 {
					severity = pkg.Groups[sevIdx].MaxSeverity
				} else {
					severity = ""
				}

				vs = append(vs, Vulnerability{
					Id:                v.Id,
					PackageName:       pkg.PackageInfo.Name,
					PackageVersion:    pkg.PackageInfo.Version,
					PackageUrl:        packageRef.Url,
					PackageEcosystem:  pkg.PackageInfo.Ecosystem,
					Source:            source,
					Severity:          severity,
					SeverityScoreKind: getSeverityScoreKind(severity),
					Summary:           v.Summary,
					Details:           v.Detail,
					FixAvailable:      hasFixAvailable(v),
				})
			}
		}
	}

	return Report{
		Project:         p,
		IsVulnerable:    len(vs) > 0,
		Vulnerabilities: vs,
	}
}

// readOSVJson reads the JSON output from osv-scanner
// and returns a Report struct with the results
func readOSVJson(data []byte) (report *OsvReport, err error) {
	err = json.Unmarshal(data, &report)
	return
}

// getSeverityScoreKind returns the SeverityScoreKind based on the severity score from OSV
func getSeverityScoreKind(severity string) SeverityScoreKind {
	if severity == "" {
		log.Debug().Msg("Severity is empty, defaulting to Unknown")
		return Unknown
	}
	floatSeverity, err := strconv.ParseFloat(severity, 32)
	if err != nil {
		log.Warn().Msgf("Failed to parse severity %v to float, defaulting to Unknown", severity)
		return Unknown
	}

	maxKind := Unknown
	for k, v := range SeverityScoreThresholds {
		if floatSeverity >= v && v >= SeverityScoreThresholds[maxKind] {
			maxKind = k
		}
	}
	return maxKind
}

// hasFixAvailable returns true if the vulnerability has at least one version that is not vulnerable
func hasFixAvailable(v osvVulnerability) bool {
	// If there is any version with a fixed event, then the vulnerability has at least one version
	// that is not vulnerable
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return true
				}
			}
		}
	}
	return false
}

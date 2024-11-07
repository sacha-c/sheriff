package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/scanner"
	"sort"
	"strconv"
	"sync"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

type SeverityScoreKind string

const (
	Critical SeverityScoreKind = "CRITICAL"
	High     SeverityScoreKind = "HIGH"
	Moderate SeverityScoreKind = "MODERATE"
	Low      SeverityScoreKind = "LOW"
	Unknown  SeverityScoreKind = "UNKNOWN"
)

// These thresholds are inferred from CSVSS reports we've seen in the wild.
// The value represents the lower bound (inclusive) of the severity score kind.
// They may need to be adjusted as we observe more vulnerabilities.
var severityScoreThresholds = map[SeverityScoreKind]float64{
	Critical: 9.0,
	High:     8.0,
	Moderate: 3.0,
	Low:      0.0,
	Unknown:  -1.0, // Arbitrary value to represent unknown severity
}

const tempScanDir = "tmp_scans"

// Representation of what a vulnerability is within our scanner
type Vulnerability struct {
	Id                string
	PackageName       string
	PackageVersion    string
	PackageUrl        string
	PackageEcosystem  string
	Source            string
	Severity          string
	SeverityScoreKind SeverityScoreKind
	Summary           string
	Details           string
	FixAvailable      bool
}

// Report is the main report representation of a project vulnerability scan.
type Report struct {
	Project         *gogitlab.Project
	IsVulnerable    bool
	Vulnerabilities []Vulnerability
	IssueUrl        string // URL of the GitLab issue. Conditionally set if --gitlab-issue is passed
	Error           bool   // Conditionally set if an error occurred during the scan
}

// GenerateVulnReport scans all projects in a GitLab group and returns a list of reports.
func GenerateVulnReport(groupPath []string, gitlabService gitlab.IService, gitService git.IService, osvService scanner.VulnScanner[scanner.OsvReport]) (reports []*Report, err error) {
	// Create a temporary directory to store the scans
	err = os.MkdirAll(tempScanDir, os.ModePerm)
	if err != nil {
		return nil, errors.New("could not create temporary directory")
	}
	defer os.RemoveAll(tempScanDir)
	log.Info().Msgf("Created temporary directory %v", tempScanDir)

	log.Info().Msg("Getting the list of projects to scan...")
	projects, err := gitlabService.GetProjectList(groupPath)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("could not get project list of group %v", groupPath), err)
	}

	// Scan all projects in parallel
	var wg sync.WaitGroup
	reportsChan := make(chan *Report, len(projects))
	for _, project := range projects {
		wg.Add(1)
		go func(reportsChan chan<- *Report) {
			log.Info().Msgf("[%v] Scanning project", project.Name)
			if report, err := scanProject(project, gitService, osvService); err != nil {
				log.Err(err).Msgf("[%v] Failed to scan project, skipping", project.Name)
				reportsChan <- &Report{Project: project, Error: true}
			} else {
				reportsChan <- report
			}
			defer wg.Done()
		}(reportsChan)
	}
	wg.Wait()
	close(reportsChan)

	// Collect the reports
	for r := range reportsChan {
		reports = append(reports, r)
	}

	sort.Slice(reports, func(i int, j int) bool {
		return len(reports[i].Vulnerabilities) > len(reports[j].Vulnerabilities)
	})

	return
}

// scanProject scans a project for vulnerabilities using the osv scanner.
func scanProject(project *gogitlab.Project, gitService git.IService, osvService scanner.VulnScanner[scanner.OsvReport]) (report *Report, err error) {
	dir, err := os.MkdirTemp(tempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		return nil, errors.Join(errors.New("failed to create project temporary directory"), err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Info().Msgf("[%v] Cloning project in %v", project.Name, dir)
	if err = gitService.Clone(dir, project.HTTPURLToRepo); err != nil {
		return nil, errors.Join(errors.New("failed to clone project"), err)
	}

	// Scan the project
	log.Info().Msgf("[%v] Running osv-scanner...", project.Name)
	osvReport, err := osvService.Scan(dir)
	if err != nil {
		log.Warn().Msgf("[%v] Failed to run osv-scanner", project.Name)
		return nil, errors.Join(errors.New("failed to run osv-scanner"), err)
	}

	report = reportFromOSV(osvReport, project)

	log.Info().Msgf("[%v] Finished scanning project", project.Name)

	return report, nil
}

// reportFromOSV maps the report from osv-scanner to our internal representation of vulnerability reports.
func reportFromOSV(r *scanner.OsvReport, p *gogitlab.Project) *Report {
	if r == nil {
		return &Report{
			Project:         p,
			IsVulnerable:    false,
			Vulnerabilities: []Vulnerability{},
		}
	}

	var vs []Vulnerability
	for _, p := range r.Results {
		for _, pkg := range p.Packages {
			for _, v := range pkg.Vulnerabilities {
				packageRef := pie.FirstOr(pie.Filter(v.References, func(ref scanner.Reference) bool { return ref.Type == scanner.PackageKind }), scanner.Reference{})
				source := filepath.Base(p.Source.Path)
				sevIdx := pie.FindFirstUsing(pkg.Groups, func(g scanner.Group) bool { return pie.Contains(g.Ids, v.Id) || pie.Contains(g.Aliases, v.Id) })
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

	return &Report{
		Project:         p,
		IsVulnerable:    len(vs) > 0,
		Vulnerabilities: vs,
	}
}

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
	for k, v := range severityScoreThresholds {
		if floatSeverity >= v && v >= severityScoreThresholds[maxKind] {
			maxKind = k
		}
	}
	return maxKind
}

func hasFixAvailable(v scanner.Vulnerability) bool {
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

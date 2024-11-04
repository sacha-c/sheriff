package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"securityscanner/internal/git"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/osv"
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
var SeverityScoreThresholds = map[SeverityScoreKind]float64{
	Critical: 9.0,
	High:     8.0,
	Moderate: 3.0,
	Low:      0.0,
}

const TempScanDir = "tmp_scans"

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

type Report struct {
	Project         *gogitlab.Project
	IsVulnerable    bool
	Vulnerabilities []Vulnerability
	IssueUrl        string // URL of the GitLab issue. Conditionally set if --gitlab-issue is passed
	Error           bool   // Conditionally set if an error occurred during the scan
}

func Scan(groupPath []string, svc *gitlab.Service) (reports []*Report, err error) {
	// Create a temporary directory to store the scans
	err = os.MkdirAll(TempScanDir, os.ModePerm)
	if err != nil {
		return nil, errors.New("could not create temporary directory")
	}
	defer os.RemoveAll(TempScanDir)
	log.Info().Msgf("Created temporary directory %v", TempScanDir)

	log.Info().Msg("Getting the list of projects to scan...")
	projects, err := svc.GetProjectList(groupPath)
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
			if report, err := scanProject(project); err != nil {
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

	return
}

func scanProject(project *gogitlab.Project) (report *Report, err error) {
	dir, err := os.MkdirTemp(TempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		return nil, errors.Join(errors.New("failed to create project temporary directory"), err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Info().Msgf("[%v] Cloning project in %v", project.Name, dir)
	if err = git.Clone(dir, project.HTTPURLToRepo); err != nil {
		return nil, errors.Join(errors.New("failed to clone project"), err)
	}

	// Scan the project
	log.Info().Msgf("[%v] Running osv-scanner...", project.Name)
	osvReport, err := osv.Scan(dir)
	if err != nil {
		log.Warn().Msgf("[%v] Failed to run osv-scanner", project.Name)
		return nil, errors.Join(errors.New("failed to run osv-scanner"), err)
	}

	report = reportFromOSV(osvReport, project)

	log.Info().Msgf("[%v] Finished scanning project", project.Name)

	return report, nil
}

func reportFromOSV(r *osv.Report, p *gogitlab.Project) *Report {
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
				packageRef := pie.FirstOr(pie.Filter(v.References, func(ref osv.Reference) bool { return ref.Type == osv.PackageKind }), osv.Reference{})
				source := filepath.Base(p.Source.Path)
				sevIdx := pie.FindFirstUsing(pkg.Groups, func(g osv.Group) bool { return pie.Contains(g.Ids, v.Id) || pie.Contains(g.Aliases, v.Id) })
				severity := pkg.Groups[sevIdx].MaxSeverity

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
	for k, v := range SeverityScoreThresholds {
		if floatSeverity >= v && v >= SeverityScoreThresholds[maxKind] {
			maxKind = k
		}
	}
	return maxKind
}

func hasFixAvailable(v osv.Vulnerability) bool {
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

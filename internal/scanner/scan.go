package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"securityscanner/internal/git"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/osv"
	"slices"
	"sync"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

const TempScanDir = "tmp_scans"

type Vulnerability struct {
	Id               string
	PackageName      string
	PackageVersion   string
	PackageUrl       string
	PackageEcosystem string
	Source           string
	Severity         string
	SeverityScore    osv.SeverityScoreKind
	Summary          string
	Details          string
}

type Report struct {
	Project         *gogitlab.Project
	IsVulnerable    bool
	Vulnerabilities []Vulnerability
	IssueUrl        string // URL of the GitLab issue. Conditionally set if --gitlab-issue is passed
	Error           bool   // Conditionally set if an error occurred during the scan
}

var SeverityScoreOrder = []osv.SeverityScoreKind{osv.Critical, osv.High, osv.Moderate, osv.Low, osv.Unknown}

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
				var severityScore osv.SeverityScoreKind = osv.Unknown
				if slices.Contains(SeverityScoreOrder, v.DatabaseSpecific.Severity) {
					severityScore = v.DatabaseSpecific.Severity
				}

				vs = append(vs, Vulnerability{
					Id:               v.Id,
					PackageName:      pkg.PackageInfo.Name,
					PackageVersion:   pkg.PackageInfo.Version,
					PackageUrl:       packageRef.Url,
					PackageEcosystem: pkg.PackageInfo.Ecosystem,
					Source:           source,
					Severity:         severity,
					SeverityScore:    severityScore,
					Summary:          v.Summary,
					Details:          v.Detail,
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

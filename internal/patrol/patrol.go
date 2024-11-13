// Package patrol provides a service to scan GitLab groups for vulnerabilities and publish reports.
package patrol

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/publish"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"sort"
	"sync"

	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

const tempScanDir = "tmp_scans"

// securityPatroller is the interface of the main security scanner service of this tool.
type securityPatroller interface {
	// Scans the given Gitlab groups and projects, creates and publishes the necessary reports
	Patrol(groupPaths []string, projectPaths []string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error
}

// sheriffService is the implementation of the SecurityPatroller interface.
type sheriffService struct {
	gitlabService gitlab.IService
	slackService  slack.IService
	gitService    git.IService
	osvService    scanner.VulnScanner[scanner.OsvReport]
}

// New creates a new securityPatroller service.
// It contains the main "loop" logic of this tool.
// A "patrol" is defined as scanning GitLab groups for vulnerabilities and publishing reports where needed.
func New(gitlabService gitlab.IService, slackService slack.IService, gitService git.IService, osvService scanner.VulnScanner[scanner.OsvReport]) securityPatroller {
	return &sheriffService{
		gitlabService: gitlabService,
		slackService:  slackService,
		gitService:    gitService,
		osvService:    osvService,
	}
}

// Patrol scans the given Gitlab groups and projects, creates and publishes the necessary reports.
func (s *sheriffService) Patrol(groupPaths []string, projectPaths []string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error {
	scanReports, err := s.scanAndGetReports(groupPaths, projectPaths)
	if err != nil {
		return errors.Join(errors.New("failed to scan projects"), err)
	}

	if gitlabIssue {
		log.Info().Msg("Creating issue in affected projects")
		publish.PublishAsGitlabIssues(scanReports, s.gitlabService)
	}

	if s.slackService != nil && slackChannel != "" {
		log.Info().Str("slackChannel", slackChannel).Msg("Posting report to slack channel")

		if err := publish.PublishAsSlackMessage(slackChannel, scanReports, groupPaths, projectPaths, s.slackService); err != nil {
			log.Error().Err(err).Msg("Failed to post slack report")
		}
	}

	publish.PublishToConsole(scanReports, printReport)

	return nil
}

func (s *sheriffService) scanAndGetReports(groupPaths []string, projectPaths []string) (reports []scanner.Report, err error) {
	// Create a temporary directory to store the scans
	err = os.MkdirAll(tempScanDir, os.ModePerm)
	if err != nil {
		return nil, errors.New("could not create temporary directory")
	}
	defer os.RemoveAll(tempScanDir)
	log.Info().Str("path", tempScanDir).Msg("Created temporary directory")
	log.Info().Strs("groups", groupPaths).Strs("projects", projectPaths).Msg("Getting the list of projects to scan")

	projects, err := s.gitlabService.GetProjectList(groupPaths, projectPaths)
	if err != nil {
		return nil, errors.Join(errors.New("could not get project list"), err)
	}

	// Scan all projects in parallel
	var wg sync.WaitGroup
	reportsChan := make(chan scanner.Report, len(projects))
	for _, project := range projects {
		wg.Add(1)
		go func(reportsChan chan<- scanner.Report) {
			defer wg.Done()
			log.Info().Str("project", project.Name).Msg("Scanning project")
			if report, err := s.scanProject(project); err != nil {
				log.Error().Err(err).Str("project", project.Name).Msg("Failed to scan project, skipping.")
				reportsChan <- scanner.Report{Project: project, Error: true}
			} else {
				reportsChan <- *report
			}
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
func (s *sheriffService) scanProject(project gogitlab.Project) (report *scanner.Report, err error) {
	dir, err := os.MkdirTemp(tempScanDir, fmt.Sprintf("%v-", project.Name))
	if err != nil {
		return nil, errors.Join(errors.New("failed to create project temporary directory"), err)
	}
	defer os.RemoveAll(dir)

	// Clone the project
	log.Info().Str("project", project.Name).Str("dir", dir).Msg("Cloning project")
	if err = s.gitService.Clone(dir, project.HTTPURLToRepo); err != nil {
		return nil, errors.Join(errors.New("failed to clone project"), err)
	}

	// Scan the project
	log.Info().Str("project", project.Name).Msg("Running osv-scanner")
	osvReport, err := s.osvService.Scan(dir)
	if err != nil {
		log.Error().Err(err).Str("project", project.Name).Msg("Failed to run osv-scanner")
		return nil, errors.Join(errors.New("failed to run osv-scanner"), err)
	}

	r := s.osvService.GenerateReport(project, osvReport)
	log.Info().Str("project", project.Name).Msg("Finished scanning with osv-scanner")

	return &r, nil
}

func validateGroupPath(path string) error {
	matched, err := regexp.Match("^\\S+(\\/\\S+)*$", []byte(path))
	if err != nil {
		return err
	}

	if !matched {
		return fmt.Errorf("invalid group path: %v", path)
	}

	return nil
}

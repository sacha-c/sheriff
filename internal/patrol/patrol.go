package patrol

import (
	"errors"
	"fmt"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/report"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"strings"

	"github.com/rs/zerolog/log"
)

// securityPatroller is the interface of the main security scanner service of this tool.
type securityPatroller interface {
	// Scans a given GitLab group path, creates and publishes the necessary reports
	Patrol(targetGroupPath string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error
}

// sheriffService is the implementation of the SecurityPatroller interface.
// It contains the main "loop" logic of this tool.
type sheriffService struct {
	gitlabService gitlab.IService
	slackService  slack.IService
	gitService    git.IService
	osvService    scanner.VulnScanner[scanner.OsvReport]
}

func New(gitlabService gitlab.IService, slackService slack.IService, gitService git.IService, osvService scanner.VulnScanner[scanner.OsvReport]) securityPatroller {
	return &sheriffService{
		gitlabService: gitlabService,
		slackService:  slackService,
		gitService:    gitService,
		osvService:    osvService,
	}
}

func (s *sheriffService) Patrol(targetGroupPath string, gitlabIssue bool, slackChannel string, printReport bool, verbose bool) error {
	groupPath, err := parseGroupPaths(targetGroupPath)
	if err != nil {
		return errors.Join(errors.New("failed to parse gitlab group path"), err)
	}

	scanReports, err := report.GenerateVulnReport(groupPath, s.gitlabService, s.gitService, s.osvService)
	if err != nil {
		return errors.Join(errors.New("failed to scan projects"), err)
	}

	if gitlabIssue {
		log.Info().Msg("Creating issue in affected projects")
		report.PublishAsGitlabIssues(scanReports, s.gitlabService)
	}

	if s.slackService != nil && slackChannel != "" {
		log.Info().Msgf("Posting report to slack channel %v", slackChannel)

		if err := report.PublishAsSlackMessage(slackChannel, scanReports, targetGroupPath, s.slackService); err != nil {
			log.Err(err).Msg("Failed to post slack report")
		}
	}

	if printReport {
		log.Info().Msgf("%#v", scanReports)
	}

	return nil
}

func parseGroupPaths(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("gitlab path missing: %v", path)
	}

	paths := strings.Split(path, "/")
	if len(paths) == 0 {
		return nil, fmt.Errorf("gitlab path incomplete: %v", path)
	}

	return paths, nil
}

package report

import (
	"fmt"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"

	"github.com/rs/zerolog/log"
)

func CreateGitlabIssues(reports []scanner.Report, s *gitlab.Service) {
	for _, r := range reports {
		if r.IsVulnerable {
			if err := s.OpenVulnerabilityIssue(r.Project, r.Report); err != nil {
				log.Err(err).Msgf("Failed to open or update issue for project %v", r.Project.Name)
			}
		} else {
			if err := s.CloseVulnerabilityIssue(r.Project); err != nil {
				log.Err(err).Msgf("Failed to close issue for project %v", r.Project.Name)
			}
		}
	}
}

func PostSlackReport(channelName string, reports []scanner.Report, s *slack.Service) (err error) {
	report := "Security Scan Report\n\n"
	for _, r := range reports {
		report += fmt.Sprintf("Project: %v | %v\n%v", r.Project.Name, r.Project.WebURL, r.Report)
	}

	if err = s.PostReport(channelName, report); err != nil {
		return
	}

	return
}

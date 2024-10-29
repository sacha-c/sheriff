package report

import (
	"fmt"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"
	"time"

	"github.com/rs/zerolog/log"
)

func CreateGitlabIssues(reports []scanner.Report, s *gitlab.Service) {
	for _, r := range reports {
		if r.IsVulnerable {
			if err := s.OpenVulnerabilityIssue(r.Project, fmt.Sprint(r)); err != nil {
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
	report := fmt.Sprintf("Security Scan Report %v\n\n", time.Now().Format(time.ANSIC))
	for _, r := range reports {
		if r.IsVulnerable {
			report += fmt.Sprintf("Project: %v | %v\n```\n%v```\n\n", r.Project.Name, r.Project.WebURL, fmt.Sprint(r))
		} else {
			report += fmt.Sprintf("Project: %v | %v\nNothing to see here :-)\n\n", r.Project.Name, r.Project.WebURL)
		}
	}

	if err = s.PostReport(channelName, report); err != nil {
		return
	}

	return
}

package report

import (
	"fmt"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"

	"github.com/rs/zerolog/log"
)

func CreateGitlabIssues(reports []scanner.Report) {
	for _, r := range reports {
		if r.IsVulnerable {
			gitlab.OpenVulnerabilityIssue(r.Project, r.Report)
		} else {
			gitlab.CloseVulnerabilityIssue(r.Project)
		}
	}
}

func PostSlackReport(channelName string, reports []scanner.Report) {
	report := "Security Scan Report\n\n"
	for _, r := range reports {
		report += fmt.Sprintf("Project: %v | %v\n%v", r.Project.Name, r.Project.WebURL, r.Report)
	}

	err := slack.PostReport(channelName, report)
	if err != nil {
		log.Err(err).Msg("Failed to post report to slack")
	}
}

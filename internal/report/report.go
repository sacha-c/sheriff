package report

import (
	"fmt"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	goslack "github.com/slack-go/slack"
)

func CreateGitlabIssues(reports []*scanner.Report, s *gitlab.Service) {
	for _, r := range reports {
		if r.IsVulnerable {
			if issue, err := s.OpenVulnerabilityIssue(r.Project, fmt.Sprint(r)); err != nil {
				log.Err(err).Msgf("Failed to open or update issue for project %v", r.Project.Name)
			} else {
				r.IssueUrl = issue.WebURL
			}
		} else {
			if err := s.CloseVulnerabilityIssue(r.Project); err != nil {
				log.Err(err).Msgf("Failed to close issue for project %v", r.Project.Name)
			}
		}
	}
}

func PostSlackReport(channelName string, reports []*scanner.Report, s *slack.Service) (err error) {
	formattedReport := formatSlackReports(reports)

	if err = s.PostMessage(channelName, formattedReport...); err != nil {
		return
	}

	return
}

func formatSlackReports(reports []*scanner.Report) []goslack.MsgOption {
	title := goslack.NewHeaderBlock(
		goslack.NewTextBlockObject(
			"plain_text",
			fmt.Sprintf("Security Scan Report %v", time.Now().Format("2006-01-02")),
			true, false,
		),
	)

	vulnerableReports := pie.Filter(reports, func(r *scanner.Report) bool { return r.IsVulnerable })
	nonVulnerableReports := pie.Filter(reports, func(r *scanner.Report) bool { return !r.IsVulnerable })

	vulnerableSections := pie.Flat(pie.Map(vulnerableReports, formatVulnerableReport))
	nonVulnerableSections := pie.Flat(pie.Map(nonVulnerableReports, formatSafeReport))

	blocks := []goslack.Block{
		title,
	}

	if len(vulnerableSections) > 0 {
		blocks = append(blocks,
			goslack.NewDividerBlock(),
			goslack.NewSectionBlock(
				goslack.NewTextBlockObject(
					"mrkdwn",
					"*--> Vulnerable Projects* 🚨",
					false, false,
				),
				nil,
				nil,
			),
		)
		blocks = append(blocks,
			vulnerableSections...,
		)
	}

	if len(nonVulnerableReports) > 0 {
		blocks = append(blocks,
			goslack.NewDividerBlock(),
			goslack.NewSectionBlock(
				goslack.NewTextBlockObject(
					"mrkdwn",
					"*--> Safe Projects* 🌟",
					false, false,
				),
				nil,
				nil,
			),
		)
		blocks = append(blocks,
			nonVulnerableSections...,
		)
	}

	options := []goslack.MsgOption{goslack.MsgOptionBlocks(blocks...)}

	return options
}

func formatVulnerableReport(r *scanner.Report) []goslack.Block {
	projectName := fmt.Sprintf("<%s|*%s*>", r.Project.WebURL, r.Project.Name)
	var reportUrl string
	if r.IssueUrl != "" {
		reportUrl = fmt.Sprintf("<%s|Full report>", r.IssueUrl)
	} else {
		reportUrl = fmt.Sprintf("<%s|Full report>", r.Project.WebURL)
	}
	vulnerabilityCount := fmt.Sprintf("*Vulnerability count*: %v", len(r.Vulnerabilities))

	return []goslack.Block{
		goslack.NewDividerBlock(),
		goslack.NewSectionBlock(
			nil,
			[]*goslack.TextBlockObject{
				goslack.NewTextBlockObject("mrkdwn", projectName, false, false),
				goslack.NewTextBlockObject("mrkdwn", reportUrl, false, false),
				goslack.NewTextBlockObject("mrkdwn", vulnerabilityCount, false, false),
			},
			nil,
		),
	}
}

func formatSafeReport(r *scanner.Report) []goslack.Block {
	return []goslack.Block{
		goslack.NewSectionBlock(
			nil,
			[]*goslack.TextBlockObject{
				goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("<%s|*%s*>", r.Project.WebURL, r.Project.Name), false, false),
			},
			nil,
		),
	}
}

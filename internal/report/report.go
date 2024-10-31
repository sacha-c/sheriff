package report

import (
	"fmt"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"
	"strconv"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	goslack "github.com/slack-go/slack"
)

func CreateGitlabIssues(reports []*scanner.Report, s *gitlab.Service) {
	for _, r := range reports {
		if r.IsVulnerable {
			if issue, err := s.OpenVulnerabilityIssue(r.Project, formatGitlabIssue(r)); err != nil {
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

func PostSlackReport(channelName string, reports []*scanner.Report, groupPath string, s *slack.Service) (err error) {
	formattedReport := formatSlackReports(reports, groupPath)

	if err = s.PostMessage(channelName, formattedReport...); err != nil {
		return
	}

	return
}

func formatGitlabIssueTable(groupName string, vs *[]scanner.Vulnerability) (report string) {
	report = fmt.Sprintf("\n## Severity: %v\n", groupName)
	report += "| OSV URL | CVSS | Ecosystem | Package | Version | Source |\n| --- | --- | --- | --- | --- | --- |\n"
	for _, vuln := range *vs {
		report += fmt.Sprintf(
			"| %v | %v | %v | %v | %v | %v |\n",
			fmt.Sprintf("https://osv.dev/%s", vuln.Id),
			vuln.Severity,
			vuln.PackageEcosystem,
			vuln.PackageName,
			vuln.PackageVersion,
			vuln.Source,
		)
	}

	return
}

func severityBiggerThan(a string, b string) bool {
	aFloat, err := strconv.ParseFloat(a, 32)
	bFloat, err := strconv.ParseFloat(b, 32)
	if err != nil {
		log.Warn().Msgf("Failed to parse vulnerability CVSS %v to float, defaulting to string comparison", a)
		return a > b
	}
	return aFloat > bFloat
}

func formatGitlabIssue(r *scanner.Report) (report string) {
	groupedVulnerabilities := pie.GroupBy(r.Vulnerabilities, func(v scanner.Vulnerability) string { return string(v.SeverityScore) })

	report = ""
	for _, groupName := range scanner.SeverityScoreOrder {
		if group, ok := groupedVulnerabilities[string(groupName)]; ok {
			sortedVulnsInGroup := pie.SortUsing(group, func(a, b scanner.Vulnerability) bool {
				return severityBiggerThan(a.Severity, b.Severity)
			})
			report += formatGitlabIssueTable(string(groupName), &sortedVulnsInGroup)
		}
	}

	return
}
func formatSlackReports(reports []*scanner.Report, groupPath string) []goslack.MsgOption {
	title := goslack.NewHeaderBlock(
		goslack.NewTextBlockObject(
			"plain_text",
			fmt.Sprintf("Security Scan Report %v", time.Now().Format("2006-01-02")),
			true, false,
		),
	)
	subtitle := goslack.NewContextBlock("subtitle", goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("Group scanned: %v", groupPath), false, false))

	reports = pie.SortUsing(reports, func(a, b *scanner.Report) bool { return len(a.Vulnerabilities) > len(b.Vulnerabilities) })

	vulnerableReports := pie.Filter(reports, func(r *scanner.Report) bool { return !r.Error && r.IsVulnerable })
	nonVulnerableReports := pie.Filter(reports, func(r *scanner.Report) bool { return !r.Error && !r.IsVulnerable })
	errorReports := pie.Filter(reports, func(r *scanner.Report) bool { return r.Error })

	vulnerableSections := pie.Flat(pie.Map(vulnerableReports, formatVulnerableReport))
	nonVulnerableSections := pie.Flat(pie.Map(nonVulnerableReports, formatSimpleReport))
	errorSections := pie.Flat(pie.Map(errorReports, formatSimpleReport))

	blocks := []goslack.Block{
		title,
		subtitle,
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

	if len(errorReports) > 0 {
		blocks = append(blocks,
			goslack.NewDividerBlock(),
			goslack.NewSectionBlock(
				goslack.NewTextBlockObject(
					"mrkdwn",
					"*--> Unsuccessfully scanned* ❌",
					false, false,
				),
				nil,
				nil,
			),
		)
		blocks = append(blocks,
			errorSections...,
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
		reportUrl = "_full report unavailable_"
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

func formatSimpleReport(r *scanner.Report) []goslack.Block {
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

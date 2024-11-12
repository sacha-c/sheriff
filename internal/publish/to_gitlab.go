package publish

import (
	"fmt"
	"sheriff/internal/gitlab"
	"sheriff/internal/scanner"
	"strconv"
	"sync"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
)

// severityScoreOrder represents the order of SeverityScoreKind by their score in descending order
// which is how we want to display it in the
var severityScoreOrder = getSeverityScoreOrder(scanner.SeverityScoreThresholds)

func PublishAsGitlabIssues(reports []*scanner.Report, s gitlab.IService) {
	var wg sync.WaitGroup
	for _, r := range reports {
		wg.Add(1)
		go func() {
			if r.IsVulnerable {
				if issue, err := s.OpenVulnerabilityIssue(r.Project, formatGitlabIssue(r)); err != nil {
					log.Error().Err(err).Str("project", r.Project.Name).Msg("Failed to open or update issue")
				} else {
					r.IssueUrl = issue.WebURL
				}
			} else {
				if err := s.CloseVulnerabilityIssue(r.Project); err != nil {
					log.Error().Err(err).Str("project", r.Project.Name).Msg("Failed to close issue")
				}
			}
			defer wg.Done()
		}()
	}
	wg.Wait()
}

func severityBiggerThan(a string, b string) bool {
	aFloat, errA := strconv.ParseFloat(a, 32)
	bFloat, errB := strconv.ParseFloat(b, 32)
	if errA != nil || errB != nil {
		log.Warn().Str("a", a).Str("b", b).Msg("Failed to parse vulnerability CVSS to float, defaulting to string comparison")
		return a > b
	}
	return aFloat > bFloat
}

func groupVulnReportsByMaxSeverityKind(reports []*scanner.Report) map[scanner.SeverityScoreKind][]*scanner.Report {
	vulnerableReports := pie.Filter(reports, func(r *scanner.Report) bool { return r.IsVulnerable })
	groupedVulnerabilities := pie.GroupBy(vulnerableReports, func(r *scanner.Report) scanner.SeverityScoreKind {
		maxSeverity := pie.SortUsing(r.Vulnerabilities, func(a, b scanner.Vulnerability) bool { return a.Severity > b.Severity })[0]

		return maxSeverity.SeverityScoreKind
	})

	return groupedVulnerabilities
}

func formatGitlabIssue(r *scanner.Report) (mdReport string) {
	groupedVulnerabilities := pie.GroupBy(r.Vulnerabilities, func(v scanner.Vulnerability) scanner.SeverityScoreKind { return v.SeverityScoreKind })

	mdReport = ""
	for _, groupName := range severityScoreOrder {
		if group, ok := groupedVulnerabilities[groupName]; ok {
			sortedVulnsInGroup := pie.SortUsing(group, func(a, b scanner.Vulnerability) bool {
				return severityBiggerThan(a.Severity, b.Severity)
			})
			mdReport += formatGitlabIssueTable(string(groupName), &sortedVulnsInGroup)
		}
	}

	return
}

func formatGitlabIssueTable(groupName string, vs *[]scanner.Vulnerability) (md string) {
	md = fmt.Sprintf("\n## Severity: %v\n", groupName)
	md += "| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |\n| --- | --- | --- | --- | --- | --- | --- |\n"
	for _, vuln := range *vs {
		md += fmt.Sprintf(
			"| %v | %v | %v | %v | %v | %v | %v |\n",
			fmt.Sprintf("https://osv.dev/%s", vuln.Id),
			vuln.Severity,
			vuln.PackageEcosystem,
			vuln.PackageName,
			vuln.PackageVersion,
			markdownBoolean(vuln.FixAvailable),
			vuln.Source,
		)
	}

	return
}

func markdownBoolean(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

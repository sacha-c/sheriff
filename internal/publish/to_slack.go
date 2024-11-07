package publish

import (
	"errors"
	"fmt"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"sort"
	"strings"
	"time"

	"github.com/elliotchance/pie/v2"
	goslack "github.com/slack-go/slack"
)

func PublishAsSlackMessage(channelName string, reports []*scanner.Report, groupPath string, s slack.IService) (err error) {
	vulnerableReportsBySeverityKind := groupVulnReportsByMaxSeverityKind(reports)

	summary := formatSummary(vulnerableReportsBySeverityKind, len(reports), groupPath)

	ts, err := s.PostMessage(channelName, summary...)
	if err != nil {
		return errors.Join(errors.New("failed to post slack summary"), err)
	}

	msgOptions := formatReportMessage(vulnerableReportsBySeverityKind)
	for _, option := range msgOptions {
		_, err = s.PostMessage(
			channelName,
			option,
			goslack.MsgOptionTS(ts), // Replies to the summary message in thread
		)
		if err != nil {
			return errors.Join(errors.New("failed to message in slack summary thread"), err)
		}
	}

	return
}
func formatSummary(reportsBySeverityKind map[scanner.SeverityScoreKind][]*scanner.Report, totalReports int, groupPath string) []goslack.MsgOption {
	title := goslack.NewHeaderBlock(
		goslack.NewTextBlockObject(
			"plain_text",
			fmt.Sprintf("Security Scan Report %v", time.Now().Format("2006-01-02")),
			true, false,
		),
	)
	subtitleGroup := goslack.NewContextBlock("subtitleGroup", goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("Group scanned: %v", groupPath), false, false))
	subtitleCount := goslack.NewContextBlock("subtitleCount", goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("Total projects scanned: %v", totalReports), false, false))

	counts := pie.Map(severityScoreOrder, func(kind scanner.SeverityScoreKind) *goslack.TextBlockObject {
		if group, ok := reportsBySeverityKind[kind]; ok {
			return goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("%v: *%v*", kind, len(group)), false, false)
		}
		return goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("%v: *%v*", kind, 0), false, false)
	})

	countsTitle := goslack.NewSectionBlock(goslack.NewTextBlockObject("mrkdwn", "*Vulnerability Counts*", false, false), nil, nil)
	countsBlock := goslack.NewSectionBlock(
		nil,
		counts,
		nil,
	)

	blocks := []goslack.Block{
		title,
		subtitleGroup,
		subtitleCount,
		countsTitle,
		countsBlock,
	}

	options := []goslack.MsgOption{goslack.MsgOptionBlocks(blocks...)}
	return options
}

func formatReportMessage(reportsBySeverityKind map[scanner.SeverityScoreKind][]*scanner.Report) (msgOptions []goslack.MsgOption) {
	text := strings.Builder{}
	for _, kind := range severityScoreOrder {
		if group, ok := reportsBySeverityKind[kind]; ok {
			if len(group) == 0 {
				continue
			}

			text.WriteString(fmt.Sprintf("Projects with vulnerabilities of *%v* severity\n", kind))
			for _, r := range group {
				projectName := fmt.Sprintf("<%s|*%s*>\n", r.Project.WebURL, r.Project.Name)
				var reportUrl string
				if r.IssueUrl != "" {
					reportUrl = fmt.Sprintf("\t<%s|Full report>\t\t", r.IssueUrl)
				} else {
					reportUrl = "\t_full report unavailable_\t\t"
				}
				vulnerabilityCount := fmt.Sprintf("\tVulnerability count: *%v*", len(r.Vulnerabilities))

				text.WriteString(projectName)
				text.WriteString(reportUrl)
				text.WriteString(vulnerabilityCount)
				text.WriteString("\n")
			}
			text.WriteString("\n")
		}
	}

	textString := text.String()
	// Slack has a 3001 character limit for messages
	splitText := splitMessage(textString, 3000)

	for _, chunk := range splitText {
		msgOptions = append(msgOptions, goslack.MsgOptionBlocks(goslack.NewSectionBlock(goslack.NewTextBlockObject("mrkdwn", chunk, false, false), nil, nil)))
	}

	return
}

// Splits a string into chunks of at most maxLen characters
// Each chunk is determined by the closest newline character
func splitMessage(s string, maxLen int) []string {
	var chunks []string
	for len(s) > maxLen {
		idx := strings.LastIndex(s[:maxLen], "\n")
		if idx == -1 {
			idx = maxLen
		}
		chunks = append(chunks, s[:idx])
		s = s[idx:]
	}
	chunks = append(chunks, s)
	return chunks
}

// getSeverityScoreOrder returns a slice of SeverityScoreKind sorted by their score in descending order
func getSeverityScoreOrder(thresholds map[scanner.SeverityScoreKind]float64) []scanner.SeverityScoreKind {
	kinds := make([]scanner.SeverityScoreKind, 0, len(thresholds))
	for kind := range thresholds {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		return thresholds[kinds[i]] > thresholds[kinds[j]]
	})

	return kinds
}

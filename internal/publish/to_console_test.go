package publish

import (
	"sheriff/internal/scanner"
	"testing"

	"github.com/stretchr/testify/assert"
	gogitlab "github.com/xanzy/go-gitlab"
)

func TestFormatReportMessageForConsole(t *testing.T) {
	reports := []scanner.Report{
		{
			Project: &gogitlab.Project{
				Name:   "project1",
				WebURL: "http://example.com",
			},
			Vulnerabilities: []scanner.Vulnerability{
				{
					Id:                "CVE-2021-1234",
					SeverityScoreKind: scanner.Critical,
				},
				{
					Id:                "CVE-2021-1235",
					SeverityScoreKind: scanner.High,
				},
			},
		},
		{
			Project: &gogitlab.Project{
				Name:   "project2",
				WebURL: "http://example2.com",
			},
			Vulnerabilities: []scanner.Vulnerability{
				{
					Id:                "CVE-2021-1235",
					SeverityScoreKind: scanner.High,
				},
			},
		},
	}

	r := formatReportsMessageForConsole(reports)

	assert.Contains(t, r, "Total number of projects scanned: 2")
	assert.Contains(t, r, "http://example.com")
	assert.Contains(t, r, "http://example2.com")
	assert.Contains(t, r, "Number of vulnerabilities: 1")
	assert.Contains(t, r, "Number of vulnerabilities: 2")

}

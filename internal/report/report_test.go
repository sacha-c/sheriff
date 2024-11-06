package report

import (
	"sheriff/internal/scanner"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Severities are grouped by severity score kind
// and they are displayed as a markdown table
func TestFormatGitlabIssue(t *testing.T) {
	mockVulnerabilities := []scanner.Vulnerability{
		{
			Id:                "test1",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "10.00",
			SeverityScoreKind: scanner.Critical,
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test2",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "0.00",
			SeverityScoreKind: scanner.Low,
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test3",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "5.00",
			SeverityScoreKind: scanner.Moderate,
			Summary:           "test",
			Details:           "test",
		},
	}

	got := formatGitlabIssue(&scanner.Report{
		Vulnerabilities: mockVulnerabilities,
	})

	want := `
## Severity: CRITICAL
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test1 | 10.00 | ecosystem | name | version | ❌ | test |

## Severity: MODERATE
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test3 | 5.00 | ecosystem | name | version | ❌ | test |

## Severity: LOW
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test2 | 0.00 | ecosystem | name | version | ❌ | test |
`

	assert.NotEmpty(t, got)
	assert.Equal(t, want, got)
}

// Within a severity kind, vulnerabilities should be sorted by severity score in descending order
func TestFormatGitlabIssueSortWithinGroup(t *testing.T) {
	mockVulnerabilities := []scanner.Vulnerability{
		{
			Id:                "test1",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "8.00",
			SeverityScoreKind: scanner.High, // This has no effect on this test
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test2",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "8.9",
			SeverityScoreKind: scanner.High, // This has no effect on this test
			Summary:           "test",
			Details:           "test",
		},
		{
			Id:                "test3",
			PackageName:       "name",
			PackageVersion:    "version",
			PackageEcosystem:  "ecosystem",
			Source:            "test",
			Severity:          "8.5",
			SeverityScoreKind: scanner.High, // This has no effect on this test
			Summary:           "test",
			Details:           "test",
		},
	}

	got := formatGitlabIssue(&scanner.Report{
		Vulnerabilities: mockVulnerabilities,
	})

	want := `
## Severity: HIGH
| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |
| --- | --- | --- | --- | --- | --- | --- |
| https://osv.dev/test2 | 8.9 | ecosystem | name | version | ❌ | test |
| https://osv.dev/test3 | 8.5 | ecosystem | name | version | ❌ | test |
| https://osv.dev/test1 | 8.00 | ecosystem | name | version | ❌ | test |
`
	assert.NotEmpty(t, got)
	assert.Equal(t, want, got)
}

func TestMarkdownBoolean(t *testing.T) {
	testCases := map[bool]string{
		true:  "✅",
		false: "❌",
	}

	for input, want := range testCases {
		t.Run(want, func(t *testing.T) {
			got := markdownBoolean(input)
			assert.Equal(t, want, got)
		})
	}
}

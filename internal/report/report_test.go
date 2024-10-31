package report

import (
	"securityscanner/internal/scanner"
	"testing"
)

func TestFormatGitlabIssue(t *testing.T) {
	mockVulnerabilities := []scanner.Vulnerability{
		{
			Id:               "test1",
			PackageName:      "name",
			PackageVersion:   "version",
			PackageEcosystem: "ecosystem",
			Source:           "test",
			Severity:         "10.00",
			SeverityScore:    "HIGH",
			Summary:          "test",
			Details:          "test",
		},
		{
			Id:               "test2",
			PackageName:      "name",
			PackageVersion:   "version",
			PackageEcosystem: "ecosystem",
			Source:           "test",
			Severity:         "0.00",
			SeverityScore:    "LOW",
			Summary:          "test",
			Details:          "test",
		},
		{
			Id:               "test3",
			PackageName:      "name",
			PackageVersion:   "version",
			PackageEcosystem: "ecosystem",
			Source:           "test",
			Severity:         "5.00",
			SeverityScore:    "MODERATE",
			Summary:          "test",
			Details:          "test",
		},
	}

	got := formatGitlabIssue(&scanner.Report{
		Vulnerabilities: mockVulnerabilities,
	})

	if got == "" {
		t.Errorf("Expected issueString to not be empty")
	}

	want := `
## Severity: HIGH
| OSV URL | CVSS | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- | --- |
| https://osv.dev/test1 | 10.00 | ecosystem | name | version | test |

## Severity: MODERATE
| OSV URL | CVSS | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- | --- |
| https://osv.dev/test3 | 5.00 | ecosystem | name | version | test |

## Severity: LOW
| OSV URL | CVSS | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- | --- |
| https://osv.dev/test2 | 0.00 | ecosystem | name | version | test |
`

	if got != want {
		t.Errorf("Expected %v\n, got %v\n", want, got)
	}
}

func TestFormatGitlabIssueSortWithinGroup(t *testing.T) {
	mockVulnerabilities := []scanner.Vulnerability{
		{
			Id:               "test1",
			PackageName:      "name",
			PackageVersion:   "version",
			PackageEcosystem: "ecosystem",
			Source:           "test",
			Severity:         "10.00",
			SeverityScore:    "HIGH",
			Summary:          "test",
			Details:          "test",
		},
		{
			Id:               "test2",
			PackageName:      "name",
			PackageVersion:   "version",
			PackageEcosystem: "ecosystem",
			Source:           "test",
			Severity:         "0.00",
			SeverityScore:    "HIGH",
			Summary:          "test",
			Details:          "test",
		},
		{
			Id:               "test3",
			PackageName:      "name",
			PackageVersion:   "version",
			PackageEcosystem: "ecosystem",
			Source:           "test",
			Severity:         "5.00",
			SeverityScore:    "HIGH",
			Summary:          "test",
			Details:          "test",
		},
	}

	got := formatGitlabIssue(&scanner.Report{
		Vulnerabilities: mockVulnerabilities,
	})

	if got == "" {
		t.Errorf("Expected issueString to not be empty")
	}

	want := `
## Severity: HIGH
| OSV URL | CVSS | Ecosystem | Package | Version | Source |
| --- | --- | --- | --- | --- | --- |
| https://osv.dev/test1 | 10.00 | ecosystem | name | version | test |
| https://osv.dev/test3 | 5.00 | ecosystem | name | version | test |
| https://osv.dev/test2 | 0.00 | ecosystem | name | version | test |
`
	if got != want {
		t.Errorf("Expected %v\n, got %v\n", want, got)
	}
}

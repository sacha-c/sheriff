package scanner

import (
	"securityscanner/internal/osv"
	"testing"
)

func TestReportFromOSV(t *testing.T) {
	mockReport := createMockReport("HIGH")
	got := reportFromOSV(mockReport, nil)

	if got == nil {
		t.Fatal("Expected report to not be nil")
	}

	if len(got.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %v", len(got.Vulnerabilities))
	}

	want := Vulnerability{
		Id:               "test",
		PackageName:      "name",
		PackageVersion:   "version",
		PackageEcosystem: "ecosystem",
		Source:           "test",
		Severity:         "test",
		SeverityScore:    "HIGH",
		Summary:          "test",
		Details:          "test",
	}

	if got.Vulnerabilities[0] != want {
		t.Errorf("Expected %v, got %v", want, got.Vulnerabilities[0])
	}
}

func TestReportFromOSVHasUnknownSeverityScore(t *testing.T) {
	mockReport := createMockReport("")
	got := reportFromOSV(mockReport, nil)

	if got == nil {
		t.Fatal("Expected report to not be nil")
	}

	if got.Vulnerabilities[0].SeverityScore != "UNKNOWN" {
		t.Errorf("Expected severity score to be UNKNOWN, got %v", got.Vulnerabilities[0].SeverityScore)
	}
}

func createMockReport(severityScore osv.SeverityScoreKind) *osv.Report {
	return &osv.Report{
		Results: []osv.Result{
			{
				Source: osv.Source{
					Path: "test",
				},
				Packages: []osv.Package{
					{
						PackageInfo: osv.PackageInfo{
							Name:      "name",
							Version:   "version",
							Ecosystem: "ecosystem",
						},
						Vulnerabilities: []osv.Vulnerability{
							{
								Id:      "test",
								Summary: "test",
								Detail:  "test",
								Version: "test",
								References: []osv.Reference{
									{
										Type: "test",
										Url:  "test",
									},
								},
								DatabaseSpecific: osv.DatabaseSpecific{
									Severity: severityScore,
								},
							},
						},
						Groups: []osv.Group{
							{
								Ids: []string{"test"},

								Aliases:     []string{"test"},
								MaxSeverity: "test",
							},
						},
					},
				},
			},
		},
	}
}

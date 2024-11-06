package report

import (
	"sheriff/internal/scanner"
	"testing"
)

func TestReportFromOSV(t *testing.T) {
	mockReport := createMockReport("10.0")
	got := reportFromOSV(mockReport, nil)

	if got == nil {
		t.Fatal("Wanted report to not be nil")
	}

	if len(got.Vulnerabilities) != 1 {
		t.Errorf("Wanted 1 vulnerability, got %v", len(got.Vulnerabilities))
	}

	want := Vulnerability{
		Id:                "test",
		PackageName:       "name",
		PackageVersion:    "version",
		PackageEcosystem:  "ecosystem",
		Source:            "test",
		Severity:          "10.0",
		SeverityScoreKind: "CRITICAL",
		Summary:           "test",
		Details:           "test",
	}

	if got.Vulnerabilities[0] != want {
		t.Errorf("Wanted %v, got %v", want, got.Vulnerabilities[0])
	}
}

func TestReportFromOSVHasCorrectSeverityKind(t *testing.T) {
	testCases := map[string]SeverityScoreKind{
		"":        Unknown,
		"unknown": Unknown,
		"0.0":     Low,
		"2.0":     Low,
		"3.0":     Moderate,
		"8.0":     High,
		"9.0":     Critical,
		"10.0":    Critical,
	}

	for input, want := range testCases {
		t.Run(input, func(t *testing.T) {
			mockReport := createMockReport(input)
			got := reportFromOSV(mockReport, nil)

			if got == nil {
				t.Fatal("Wanted report to not be nil")
			}

			if got.Vulnerabilities[0].SeverityScoreKind != want {
				t.Errorf("Wanted severity score to be %v, got %v", want, got.Vulnerabilities[0].SeverityScoreKind)
			}
		})
	}
}

func TestReportContainsHasAvailableFix(t *testing.T) {
	mockReport := createMockReport("10.0", scanner.Affected{
		Ranges: []scanner.Range{
			{
				Events: []scanner.Event{
					{
						Introduced: "0.0.0",
					},
					{
						Fixed: "1.0.0",
					},
				},
			},
		},
	})
	got := reportFromOSV(mockReport, nil)

	if got == nil {
		t.Fatal("Wanted report to not be nil")
	}

	if !got.Vulnerabilities[0].FixAvailable {
		t.Error("Wanted fix to be available")
	}
}

func createMockReport(maxSeverity string, affectedVersions ...scanner.Affected) *scanner.OsvReport {
	return &scanner.OsvReport{
		Results: []scanner.Result{
			{
				Source: scanner.Source{
					Path: "test",
				},
				Packages: []scanner.Package{
					{
						PackageInfo: scanner.PackageInfo{
							Name:      "name",
							Version:   "version",
							Ecosystem: "ecosystem",
						},
						Vulnerabilities: []scanner.Vulnerability{
							{
								Id:      "test",
								Summary: "test",
								Detail:  "test",
								Version: "test",
								References: []scanner.Reference{
									{
										Type: "test",
										Url:  "test",
									},
								},
								DatabaseSpecific: scanner.DatabaseSpecific{
									Severity: "whatever",
								},
								Affected: affectedVersions,
							},
						},
						Groups: []scanner.Group{
							{
								Ids: []string{"test"},

								Aliases:     []string{"test"},
								MaxSeverity: maxSeverity,
							},
						},
					},
				},
			},
		},
	}
}

package scanner

import (
	"sheriff/internal/osv"
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
	mockReport := createMockReport("10.0", osv.Affected{
		Ranges: []osv.Range{
			{
				Events: []osv.Event{
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

func createMockReport(maxSeverity string, affectedVersions ...osv.Affected) *osv.Report {
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
									Severity: "whatever",
								},
								Affected: affectedVersions,
							},
						},
						Groups: []osv.Group{
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

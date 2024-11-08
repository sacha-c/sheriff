package scanner

import (
	"sheriff/internal/shell"
	"testing"

	"io"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/xanzy/go-gitlab"
)

func TestReadOSVJson(t *testing.T) {
	byteValue, err := readMockJsonData("testdata/osv-output.json")
	if err != nil {
		t.Fatal(err)
	}

	var got *OsvReport
	got, err = readOSVJson(byteValue)

	assert.Nil(t, err)
	assert.Equal(t, 1, len(got.Results))
	assert.Equal(t, 2, len(got.Results[0].Packages))

	firstPackage := got.Results[0].Packages[0]

	assert.Equal(t, 1, len(firstPackage.Vulnerabilities))
	assert.Equal(t, 1, len(firstPackage.Vulnerabilities[0].Affected))

	t.Run("Test affected ranges", func(t *testing.T) {
		assert.Equal(t, 1, len(firstPackage.Vulnerabilities[0].Affected[0].Ranges))
		assert.Equal(t, 2, len(firstPackage.Vulnerabilities[0].Affected[0].Ranges[0].Events))
		assert.Equal(t, "2.8.0", firstPackage.Vulnerabilities[0].Affected[0].Ranges[0].Events[1].Fixed)
	})

}

func TestScanReturnsFullReport(t *testing.T) {
	// Mock the command runner
	originalShellCommandRunner := shell.ShellCommandRunner
	shell.ShellCommandRunner = &mockCommandRunner{FixturePath: "testdata/osv-output.json", ExitCode: 1}

	defer func() {
		shell.ShellCommandRunner = originalShellCommandRunner
	}()

	svc := NewOsvScanner()

	report, err := svc.Scan("test-dir")

	assert.Nil(t, err)
	assert.Equal(t, 1, len(report.Results))
	assert.Equal(t, 2, len(report.Results[0].Packages))
	assert.Equal(t, 1, len(report.Results[0].Packages[0].Vulnerabilities))
}

func TestScanWithZeroExitCodeReturnsEmptyReport(t *testing.T) {
	// Mock the command runner
	originalShellCommandRunner := shell.ShellCommandRunner
	shell.ShellCommandRunner = &mockCommandRunner{FixturePath: "testdata/osv-output.json", ExitCode: 0}

	defer func() {
		shell.ShellCommandRunner = originalShellCommandRunner
	}()

	svc := NewOsvScanner()

	report, err := svc.Scan("test-dir")

	assert.Nil(t, err)
	assert.Nil(t, report)
}

type mockCommandRunner struct {
	FixturePath string
	ExitCode    int
}

func (m *mockCommandRunner) Run(shell.CommandInput) (shell.CommandOutput, error) {
	out, err := readMockJsonData(m.FixturePath)
	if err != nil {
		return shell.CommandOutput{
			Output:   nil,
			ExitCode: -1,
		}, err
	}

	return shell.CommandOutput{
		Output:   out,
		ExitCode: m.ExitCode,
	}, nil
}

func TestGenerateReportOSV(t *testing.T) {
	mockReport := createMockReport("10.0")
	s := osvScanner{}
	got := s.GenerateReport(&gitlab.Project{}, mockReport)

	assert.NotNil(t, got)
	assert.Len(t, got.Vulnerabilities, 1)

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

	assert.Equal(t, want, got.Vulnerabilities[0])
}

func TestGenerateReportOSVHasCorrectSeverityKind(t *testing.T) {
	s := osvScanner{}
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
			got := s.GenerateReport(&gitlab.Project{}, mockReport)

			assert.NotNil(t, got)
			assert.Equal(t, want, got.Vulnerabilities[0].SeverityScoreKind)
		})
	}
}

func TestReportContainsHasAvailableFix(t *testing.T) {
	s := osvScanner{}
	mockReport := createMockReport("10.0", osvAffected{
		Ranges: []osvRange{
			{
				Events: []osvEvent{
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
	got := s.GenerateReport(&gitlab.Project{}, mockReport)

	assert.NotNil(t, got)
	assert.Len(t, got.Vulnerabilities, 1)
	assert.True(t, got.Vulnerabilities[0].FixAvailable)
}

func createMockReport(maxSeverity string, affectedVersions ...osvAffected) *OsvReport {
	return &OsvReport{
		Results: []osvResult{
			{
				Source: osvSource{
					Path: "test",
				},
				Packages: []osvPackage{
					{
						PackageInfo: osvPackageInfo{
							Name:      "name",
							Version:   "version",
							Ecosystem: "ecosystem",
						},
						Vulnerabilities: []osvVulnerability{
							{
								Id:      "test",
								Summary: "test",
								Detail:  "test",
								Version: "test",
								References: []osvReference{
									{
										Type: "test",
										Url:  "test",
									},
								},
								DatabaseSpecific: osvDatabaseSpecific{
									Severity: "whatever",
								},
								Affected: affectedVersions,
							},
						},
						Groups: []osvGroup{
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

func readMockJsonData(filepath string) ([]byte, error) {
	jsonFile, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	return byteValue, nil
}

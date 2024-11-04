package osv

import (
	"securityscanner/internal/shell"
	"testing"

	"io"
	"os"
)

func TestReadOSVJson(t *testing.T) {
	byteValue, err := readMockJsonData("testdata/osv-output.json")
	if err != nil {
		t.Fatal(err)
	}

	var got *Report
	got, err = readOSVJson(byteValue)

	if err != nil {
		t.Fatal(err)
	}

	if len(got.Results) != 1 {
		t.Errorf("Wanted 1 result, got %v", len(got.Results))
	}

	if len(got.Results[0].Packages) != 2 {
		t.Errorf("Wanted 2 packages, got %v", len(got.Results[0].Packages))
	}
	firstPackage := got.Results[0].Packages[0]

	if len(firstPackage.Vulnerabilities) != 1 {
		t.Errorf("Wanted 1 vulnerability, got %v", len(firstPackage.Vulnerabilities))
	}

	if len(firstPackage.Vulnerabilities[0].Affected) != 1 {
		t.Errorf("Wanted 1 affected, got %v", len(firstPackage.Vulnerabilities[0].Affected))
	}

	t.Run("Test affected ranges", func(t *testing.T) {

		if len(firstPackage.Vulnerabilities[0].Affected[0].Ranges) != 1 {
			t.Errorf("Wanted 1 range, got %v", len(firstPackage.Vulnerabilities[0].Affected[0].Ranges))
		}

		if len(firstPackage.Vulnerabilities[0].Affected[0].Ranges[0].Events) != 2 {
			t.Errorf("Wanted 2 events, got %v", len(firstPackage.Vulnerabilities[0].Affected[0].Ranges[0].Events))
		}

		if firstPackage.Vulnerabilities[0].Affected[0].Ranges[0].Events[1].Fixed != "2.8.0" {
			t.Errorf("Wanted fixed version to be '2.8.0', got %v", firstPackage.Vulnerabilities[0].Affected[0].Ranges[0].Events[1].Fixed)
		}
	})

}

func TestScanReturnsFullReport(t *testing.T) {
	// Mock the command runner
	originalShellCommandRunner := shell.ShellCommandRunner
	shell.ShellCommandRunner = &mockCommandRunner{FixturePath: "testdata/osv-output.json", ExitCode: 1}

	defer func() {
		shell.ShellCommandRunner = originalShellCommandRunner
	}()

	report, err := Scan("test-dir")
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Results) != 1 {
		t.Errorf("Wanted 1 result, got %v", len(report.Results))
	}
}

func TestScanWithZeroExitCodeReturnsEmptyReport(t *testing.T) {
	// Mock the command runner
	originalShellCommandRunner := shell.ShellCommandRunner
	shell.ShellCommandRunner = &mockCommandRunner{FixturePath: "testdata/osv-output.json", ExitCode: 0}

	defer func() {
		shell.ShellCommandRunner = originalShellCommandRunner
	}()

	report, err := Scan("test-dir")
	if err != nil {
		t.Fatalf("Wanted no error, got %v", err)
	}

	if report != nil {
		t.Errorf("Wanted report to be nil, but got %v", report)
	}

}

type mockCommandRunner struct {
	FixturePath string
	ExitCode    int
}

func (m *mockCommandRunner) Run(command string, args ...string) (shell.CommandOutput, error) {
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

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
		t.Errorf("Expected 1 result, got %v", len(got.Results))
	}

	if len(got.Results[0].Packages) != 2 {
		t.Errorf("Expected 2 packages, got %v", len(got.Results[0].Packages))
	}
	firstPackage := got.Results[0].Packages[0]

	if len(firstPackage.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %v", len(firstPackage.Vulnerabilities))
	}
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
		t.Errorf("Expected 1 result, got %v", len(report.Results))
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
		t.Fatalf("Expected no error, got %v", err)
	}

	if report != nil {
		t.Errorf("Expected report to be nil, but got %v", report)
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

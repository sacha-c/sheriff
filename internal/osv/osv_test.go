package osv

import (
	"securityscanner/internal/shell"
	"testing"

	"io"
	"os"

	"github.com/stretchr/testify/assert"
)

func TestReadOSVJson(t *testing.T) {
	byteValue, err := readMockJsonData("testdata/osv-output.json")
	if err != nil {
		t.Fatal(err)
	}

	var got *Report
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

	svc := NewService()

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

	svc := NewService()

	report, err := svc.Scan("test-dir")

	assert.Nil(t, err)
	assert.Nil(t, report)
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

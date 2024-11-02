package shell

import "testing"

func TestSuccessfulCommand(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run("echo", "hello")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if string(output.Output) != "hello\n" {
		t.Errorf("Expected output to be 'hello', got %s", string(output.Output))
	}

	if output.ExitCode != 0 {
		t.Errorf("Expected exit code to be 0, got %d", output.ExitCode)
	}
}

func TestFailedCommand(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run("ls", "nonexistent")

	if err == nil {
		t.Error("Expected error, got nil")
	}

	if string(output.Output) != "" {
		t.Errorf("Expected output to be empty, got %s", string(output.Output))
	}

	if output.ExitCode == 0 {
		t.Errorf("Expected exit code to be non-zero, got %d", output.ExitCode)
	}
}

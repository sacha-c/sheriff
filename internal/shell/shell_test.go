package shell

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSuccessfulCommand(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run(CommandInput{Name: "echo", Args: []string{"hello"}, Timeout: 1 * time.Second})

	assert.Nil(t, err)
	assert.Equal(t, "hello\n", string(output.Output))
	assert.Equal(t, 0, output.ExitCode)
}

func TestCommandWithNoArgs(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run(CommandInput{Name: "echo", Args: []string{}, Timeout: 1 * time.Second})

	assert.Nil(t, err)
	assert.Equal(t, "\n", string(output.Output))
	assert.Equal(t, 0, output.ExitCode)
}

func TestCommandTimeoutError(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run(CommandInput{Name: "sleep", Args: []string{"1"}, Timeout: 1 * time.Millisecond})

	assert.NotNil(t, err)
	assert.Equal(t, "", string(output.Output))
	assert.Equal(t, -1, output.ExitCode)
}

func TestCommandWithNoTimeout(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run(CommandInput{Name: "echo", Args: []string{"hello"}})

	assert.Nil(t, err)
	assert.Equal(t, "hello\n", string(output.Output))
	assert.Equal(t, 0, output.ExitCode)
}

func TestFailedCommand(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run(CommandInput{Name: "ls", Args: []string{"/nonexistent"}, Timeout: 1 * time.Second})

	assert.NotNil(t, err)
	assert.Equal(t, "", string(output.Output))
	assert.NotEqual(t, 0, output.ExitCode)
}

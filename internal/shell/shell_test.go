package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuccessfulCommand(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run("echo", "hello")

	assert.Nil(t, err)
	assert.Equal(t, "hello\n", string(output.Output))
	assert.Equal(t, 0, output.ExitCode)
}

func TestFailedCommand(t *testing.T) {
	runner := &shellCommandRunner{}

	output, err := runner.Run("ls", "nonexistent")

	assert.NotNil(t, err)
	assert.Equal(t, "", string(output.Output))
	assert.NotEqual(t, 0, output.ExitCode)
}

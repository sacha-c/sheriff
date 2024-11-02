package shell

import (
	"errors"
	"os/exec"
)

type CommandRunnerInterface interface {
	Run(name string, arg ...string) (CommandOutput, error)
}
type CommandOutput struct {
	Output   []byte
	ExitCode int
}

// CommandRunner is a struct that implements the CommandRunnerInterface
// It is used to run shell commands, encapsulating the exec.Command function.
type shellCommandRunner struct{}

func (c *shellCommandRunner) Run(name string, arg ...string) (CommandOutput, error) {
	cmd := exec.Command(name, arg...)
	out, err := cmd.Output()

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			// Something went wrong, but the command did not exit at all with an exit code
			exitCode = -1
		}
	}

	return CommandOutput{
		Output:   out,
		ExitCode: exitCode,
	}, err
}

// ShellCommandRunner is a global variable that is used to run shell commands.
var ShellCommandRunner CommandRunnerInterface = &shellCommandRunner{}

package shell

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const defaultTimeout = 5 * time.Second

type CommandRunnerInterface interface {
	Run(in CommandInput) (CommandOutput, error)
}
type CommandOutput struct {
	Output   []byte
	ExitCode int
}

type CommandInput struct {
	Name    string
	Args    []string
	Timeout time.Duration
}

// CommandRunner is a struct that implements the CommandRunnerInterface
// It is used to run shell commands, encapsulating the exec.Command function.
type shellCommandRunner struct{}

func (c *shellCommandRunner) Run(in CommandInput) (CommandOutput, error) {
	if in.Timeout == 0 {
		in.Timeout = defaultTimeout
	}
	ctx, _ := context.WithTimeout(context.Background(), in.Timeout)
	cmd := exec.CommandContext(ctx, in.Name, in.Args...)
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

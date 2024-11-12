package cli

import "testing"

func TestApp(t *testing.T) {
	App([]string{}) // no arguments will just print the usage. We expect no errors.
}

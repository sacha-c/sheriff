package patrol

import (
	"errors"
	"os"
	"sheriff/internal/scanner"

	"github.com/BurntSushi/toml"
)

func getConfiguration(filename string) (config scanner.ProjectConfig, found bool, err error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return scanner.ProjectConfig{}, false, nil
	} else if err != nil {
		return config, false, errors.Join(errors.New("unexpected error when attempting to get project configuration"), err)
	}

	_, err = toml.DecodeFile(filename, &config)
	if err != nil {
		return config, true, errors.Join(errors.New("failed to decode project configuration"), err)
	}

	return config, true, nil
}

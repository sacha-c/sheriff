package cli

import (
	"errors"
	"fmt"
	"os"
	"sheriff/internal/log"

	zerolog "github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

func CombineBeforeFuncs(beforeFuncs ...cli.BeforeFunc) cli.BeforeFunc {
	return func(cCtx *cli.Context) error {
		for _, beforeFunc := range beforeFuncs {
			if err := beforeFunc(cCtx); err != nil {
				return err
			}
		}
		return nil
	}
}

func ConfigureLogs(cCtx *cli.Context) error {
	log.ConfigureLogs(cCtx.Bool(verboseFlag))
	zerolog.Info().Msg("Logging configured")
	return nil
}

func GetConfigFileLoader(flags []cli.Flag, fileNameFlag string) cli.BeforeFunc {
	return func(cCtx *cli.Context) error {
		fileName := cCtx.String(fileNameFlag)
		if _, err := os.Stat(fileName); err == nil {
			// Config file exists
			zerolog.Info().Str("file", fileName).Msg("Loading configuration file")
			return altsrc.InitInputSourceWithContext(flags, func(cCtx *cli.Context) (altsrc.InputSourceContext, error) {
				return altsrc.NewTomlSourceFromFile(fileName)
			})(cCtx)
		} else if errors.Is(err, os.ErrNotExist) {
			if cCtx.IsSet(fileNameFlag) {
				// Config file was explicitly set but does not exist
				return fmt.Errorf("config file %v does not exist", fileName)
			}
			zerolog.Info().Str("file", fileName).Msg("No configuration file found")
			return nil // No config file, do nothing
		} else {
			// Error stating config file
			return errors.Join(fmt.Errorf("failed to stat config file %s", fileName), err)
		}
	}
}

package main

import (
	"os"
	"securityscanner/internal/report"
	"securityscanner/internal/scanner"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "securityscanner",
		Usage: "fight dangerous dependencies!",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "slack-channel",
				Usage: "Slack channel to post the security report.",
			},
			&cli.BoolFlag{
				Name:  "gitlab-issue",
				Usage: "Enable GitLab issue creation in projects affected by vulnerabilities.",
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "Enable verbose logging",
			},
		},
		Action: func(cCtx *cli.Context) error {
			configureLogs(cCtx.Bool("verbose"))

			namespace := cCtx.Args().First()
			if namespace == "" {
				log.Fatal().Msg("Please enter a gitlab namespace to scan.")
			}

			scan_report := scanner.Scan(namespace)

			if gitlab_issue := cCtx.Bool("gitlab-issue"); gitlab_issue {
				log.Info().Msg("Creating issue in affected projects")
				report.CreateGitlabIssues(scan_report)
			}

			if slack_channel := cCtx.String("slack-channel"); slack_channel != "" {
				log.Info().Msgf("Posting report to slack channel %v", slack_channel)
				report.PostSlackReport(slack_channel, scan_report)
			}

			return nil
		},
		Args:      true,
		ArgsUsage: "<gitlab namespace to scan>",
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("Could not run application")
	}
}

func configureLogs(verbose bool) {
	// UNIX Time is faster and smaller than most timestamps
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

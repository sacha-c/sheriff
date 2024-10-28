package main

import (
	"os"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/report"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"

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
			&cli.StringFlag{
				Name:    "gitlab-token",
				Usage:   "Token to access the Gitlab API.",
				EnvVars: []string{"GITLAB_TOKEN"},
			},
			&cli.StringFlag{
				Name:    "slack-token",
				Usage:   "Token to access the Slack API.",
				EnvVars: []string{"SLACK_TOKEN"},
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

			gitlabSvc, err := gitlab.NewService(cCtx.String("gitlab-token"))
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to create gitlab client.")
			}

			scan_report, err := scanner.Scan(namespace, gitlabSvc)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to scan projects.")
			}

			if gitlab_issue := cCtx.Bool("gitlab-issue"); gitlab_issue {
				log.Info().Msg("Creating issue in affected projects")
				report.CreateGitlabIssues(scan_report, gitlabSvc)
			}

			if slack_channel := cCtx.String("slack-channel"); slack_channel != "" {
				log.Info().Msgf("Posting report to slack channel %v", slack_channel)

				slackSvc := slack.New(cCtx.String("slack-token"))

				if err := report.PostSlackReport(slack_channel, scan_report, slackSvc); err != nil {
					log.Err(err).Msg("Failed to post slack report")
				}
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

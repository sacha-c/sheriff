package main

import (
	"errors"
	"os"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/log"
	"sheriff/internal/osv"
	"sheriff/internal/patrol"
	"sheriff/internal/slack"

	zerolog "github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

type CommandCategory string

const (
	Reporting     CommandCategory = "Reporting:"
	Tokens        CommandCategory = "Tokens:"
	Miscellaneous CommandCategory = "Miscellaneous:"
)

func main() {
	app := &cli.App{
		Name:    "sheriff",
		Usage:   "Fighting dangerous dangerous dependencies since 2024.",
		Version: "0.12.1",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "verbose",
				Usage:       "Enable verbose logging",
				Category:    string(Miscellaneous),
				DefaultText: "false",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "patrol",
				Usage: "Tell sheriff to patrol a GitLab group looking for vulnerabilities",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "report-slack-channel",
						Usage:    "Enable reporting to Slack through messages in the specified channel.",
						Category: string(Reporting),
					},
					&cli.BoolFlag{
						Name:        "report-gitlab",
						Usage:       "Enable reporting to GitLab through issue creation in projects affected by vulnerabilities.",
						Category:    string(Reporting),
						DefaultText: "false",
					},
					&cli.BoolFlag{
						Name:        "report-stdout",
						Usage:       "Enable reporting to stdout.",
						Category:    string(Reporting),
						DefaultText: "false",
					},
					&cli.StringFlag{
						Name:     "gitlab-token",
						Usage:    "Token to access the Gitlab API.",
						Required: true,
						EnvVars:  []string{"GITLAB_TOKEN"},
						Category: string(Tokens),
					},
					&cli.StringFlag{
						Name:     "slack-token",
						Usage:    "Token to access the Slack API.",
						EnvVars:  []string{"SLACK_TOKEN"},
						Category: string(Tokens),
					},
				},
				Action: func(cCtx *cli.Context) error {
					verbose := cCtx.Bool("verbose")
					log.ConfigureLogs(cCtx.Bool("verbose"))

					// Ensure GitLab group path is provided
					targetGroupPath := cCtx.Args().First()
					if targetGroupPath == "" {
						return errors.New("gitlab group path argument missing")
					}

					// Create services
					gitlabService, err := gitlab.New(cCtx.String("gitlab-token"))
					if err != nil {
						return errors.Join(errors.New("failed to create GitLab service"), err)
					}

					slackService, err := slack.New(cCtx.String("slack-token"), verbose)
					if err != nil {
						return errors.Join(errors.New("failed to create Slack service"), err)
					}

					gitService := git.New(cCtx.String("gitlab-token"))
					osvService := osv.New()

					patrolService := patrol.New(gitlabService, slackService, gitService, osvService)

					// Run the scan
					if err := patrolService.Patrol(
						targetGroupPath,
						cCtx.Bool("report-gitlab"),
						cCtx.String("report-slack-channel"),
						cCtx.Bool("print-report"),
						verbose,
					); err != nil {
						return errors.Join(errors.New("failed to scan"), err)
					}

					return nil
				},
				Args:      true,
				ArgsUsage: "full/path/to/gitlab/group",
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		zerolog.Fatal().Err(err).Msg("Could not run application")
	}
}

package main

import (
	"os"
	"securityscanner/internal/git"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/log"
	"securityscanner/internal/osv"
	"securityscanner/internal/scan"
	"securityscanner/internal/slack"

	zerolog "github.com/rs/zerolog/log"
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
				Name:  "print-report",
				Usage: "Print report to standard output",
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
			// Configure logging
			verbose := cCtx.Bool("verbose")
			log.ConfigureLogs(verbose)

			// Ensure GitLab group path is provided
			targetGroupPath := cCtx.Args().First()
			if targetGroupPath == "" {
				zerolog.Fatal().Msg("Gitlab group path missing")
			}

			// Create services
			gitlabService, err := gitlab.New(cCtx.String("gitlab-token"))
			if err != nil {
				zerolog.Fatal().Err(err).Msg("Failed to create GitLab service")
			}

			slackService, err := slack.New(cCtx.String("slack-token"), verbose)
			if err != nil {
				zerolog.Fatal().Err(err).Msg("Failed to create Slack service")
			}

			gitService := git.New(cCtx.String("gitlab-token"))
			osvService := osv.New()

			scanService := scan.New(gitlabService, slackService, gitService, osvService)

			// Run the scan
			if err := scanService.Scan(
				targetGroupPath,
				cCtx.Bool("gitlab-issue"),
				cCtx.String("slack-channel"),
				cCtx.Bool("print-report"),
				verbose,
			); err != nil {
				zerolog.Fatal().Err(err).Msg("Failed to scan")
			}

			return nil
		},
		Args:      true,
		ArgsUsage: "full/path/to/gitlab/group",
	}

	if err := app.Run(os.Args); err != nil {
		zerolog.Fatal().Err(err).Msg("Could not run application")
	}
}

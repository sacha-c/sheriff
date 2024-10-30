package main

import (
	"fmt"
	"os"
	"securityscanner/internal/gitlab"
	"securityscanner/internal/report"
	"securityscanner/internal/scanner"
	"securityscanner/internal/slack"
	"strings"

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
			verbose := cCtx.Bool("verbose")
			targetGroupPath := cCtx.Args().First()

			configureLogs(verbose)

			if targetGroupPath == "" {
				log.Fatal().Msg("Gitlab group path missing")
			}

			groupPath, err := parseGroupPaths(targetGroupPath)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to parse gitlab group path")
			}

			gitlabSvc, err := gitlab.NewService(cCtx.String("gitlab-token"))
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to create gitlab client.")
			}

			scanReports, err := scanner.Scan(groupPath, gitlabSvc)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to scan projects.")
			}

			if gitlab_issue := cCtx.Bool("gitlab-issue"); gitlab_issue {
				log.Info().Msg("Creating issue in affected projects")
				report.CreateGitlabIssues(scanReports, gitlabSvc)
			}

			if slack_channel := cCtx.String("slack-channel"); slack_channel != "" {
				log.Info().Msgf("Posting report to slack channel %v", slack_channel)

				slackSvc := slack.New(cCtx.String("slack-token"), verbose)

				if err := report.PostSlackReport(slack_channel, scanReports, targetGroupPath, slackSvc); err != nil {
					log.Err(err).Msg("Failed to post slack report")
				}
			}

			if cCtx.Bool("print-report") {
				log.Info().Msgf("%#v", scanReports)
			}

			return nil
		},
		Args:      true,
		ArgsUsage: "full/path/to/gitlab/group",
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

func parseGroupPaths(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("gitlab path missing: %v", path)
	}

	paths := strings.Split(path, "/")
	if len(paths) == 0 {
		return nil, fmt.Errorf("gitlab path incomplete: %v", path)
	}

	return paths, nil
}

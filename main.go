package main

import (
	"log"
	"os"
	"securityscanner/internal/report"
	"securityscanner/internal/scanner"

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
		},
		Action: func(cCtx *cli.Context) error {
			namespace := cCtx.Args().First()
			if namespace == "" {
				log.Fatal("Please enter a gitlab namespace to scan.")
			}

			scan_report := scanner.Scan(namespace)

			if gitlab_issue := cCtx.Bool("gitlab-issue"); gitlab_issue {
				log.Default().Printf("Creating issue in affected projects")
				report.CreateGitlabIssues(scan_report)
			}

			if slack_channel := cCtx.String("slack-channel"); slack_channel != "" {
				log.Default().Printf("Posting report to slack channel %v", slack_channel)
				report.PostSlackReport(slack_channel, scan_report)
			}

			return nil
		},
		Args:      true,
		ArgsUsage: "<gitlab namespace to scan>",
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

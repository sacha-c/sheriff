package cli

import (
	"errors"
	"sheriff/internal/git"
	"sheriff/internal/gitlab"
	"sheriff/internal/patrol"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"

	zerolog "github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

const configFlag = "config"
const verboseFlag = "verbose"
const testingFlag = "testing"
const reportSlackChannelFlag = "report-slack-channel"
const reportGitlabFlag = "report-gitlab-issue"
const reportStdoutFlag = "report-stdout"
const publicSlackChannelFlag = "public-slack-channel"
const gitlabTokenFlag = "gitlab-token"
const slackTokenFlag = "slack-token"

var PatrolFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  configFlag,
		Value: "sheriff.toml",
	},
	&cli.BoolFlag{
		Name:     verboseFlag,
		Usage:    "Enable verbose logging",
		Category: string(Miscellaneous),
		Value:    false,
	},
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     testingFlag,
		Usage:    "Enable testing mode. This can enable features that are not safe for production use.",
		Category: string(Miscellaneous),
		Value:    false,
	}),
	altsrc.NewStringFlag(&cli.StringFlag{
		Name:     reportSlackChannelFlag,
		Usage:    "Enable reporting to Slack through messages in the specified channel.",
		Category: string(Reporting),
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     reportGitlabFlag,
		Usage:    "Enable reporting to GitLab through issue creation in projects affected by vulnerabilities.",
		Category: string(Reporting),
		Value:    false,
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     reportStdoutFlag,
		Usage:    "Enable reporting to stdout.",
		Category: string(Reporting),
		Value:    false,
	}),
	altsrc.NewBoolFlag(&cli.BoolFlag{
		Name:     publicSlackChannelFlag,
		Usage:    "Allow the slack report to be posted to a public channel. Note that reports may contain sensitive information which should not be disclosed on a public channel, for this reason this flag will only be enabled when combined with the testing flag.",
		Category: string(Reporting),
		Value:    false,
	}),
	// Secret tokens
	&cli.StringFlag{
		Name:     gitlabTokenFlag,
		Usage:    "Token to access the Gitlab API.",
		Required: true,
		EnvVars:  []string{"GITLAB_TOKEN"},
		Category: string(Tokens),
	},
	&cli.StringFlag{
		Name:     slackTokenFlag,
		Usage:    "Token to access the Slack API.",
		EnvVars:  []string{"SLACK_TOKEN"},
		Category: string(Tokens),
	},
}

func PatrolAction(cCtx *cli.Context) error {
	verbose := cCtx.Bool(verboseFlag)

	var publicChannelsEnabled bool
	if cCtx.Bool(testingFlag) {
		zerolog.Warn().Msg("Testing mode enabled. This may enable features that are not safe for production use.")
		publicChannelsEnabled = cCtx.Bool(publicSlackChannelFlag)
	}

	// Ensure GitLab group path is provided
	targetGroupPath := cCtx.Args().First()
	if targetGroupPath == "" {
		return errors.New("gitlab group path argument missing")
	}

	// Create services
	gitlabService, err := gitlab.New(cCtx.String(gitlabTokenFlag))
	if err != nil {
		return errors.Join(errors.New("failed to create GitLab service"), err)
	}

	slackService, err := slack.New(cCtx.String(slackTokenFlag), publicChannelsEnabled, verbose)
	if err != nil {
		return errors.Join(errors.New("failed to create Slack service"), err)
	}

	gitService := git.New(cCtx.String(gitlabTokenFlag))
	osvService := scanner.NewOsvScanner()

	patrolService := patrol.New(gitlabService, slackService, gitService, osvService)

	// Run the scan
	if err := patrolService.Patrol(
		targetGroupPath,
		cCtx.Bool(reportGitlabFlag),
		cCtx.String(reportSlackChannelFlag),
		cCtx.Bool(reportStdoutFlag),
		verbose,
	); err != nil {
		return errors.Join(errors.New("failed to scan"), err)
	}

	return nil
}

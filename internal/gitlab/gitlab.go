package gitlab

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
)

const VulnerabilityIssueTitle = "SecurityScanner - Vulnerability report"

func GetProjectList(namespace string) (projects []*gitlab.Project) {
	git, err := gitlab.NewClient(os.Getenv("GITLAB_TOKEN"))
	if err != nil {
		log.Panic().Err(err).Msg("Failed to create client")
	}

	groups, _, err := git.Groups.ListGroups(&gitlab.ListGroupsOptions{
		TopLevelOnly: gitlab.Ptr(true),
		Search:       gitlab.Ptr(namespace),
	})
	if err != nil {
		log.Panic().Err(err).Msg("Failed to fetch list of groups")
	}
	if len(groups) == 0 {
		log.Panic().Msgf("Group '%v' not found", namespace)
	}

	group := groups[0]

	log.Info().Msgf("Fetching projects for group '%v'", group.Name)
	projects, _, err = git.Groups.ListGroupProjects(group.ID,
		&gitlab.ListGroupProjectsOptions{
			Archived:         gitlab.Ptr(false),
			Simple:           gitlab.Ptr(true),
			IncludeSubGroups: gitlab.Ptr(true),
		})
	if err != nil {
		log.Panic().Err(err).Msg("Failed to fetch list of projects")
	}

	return
}

func getVulnerabilityIssue(project *gitlab.Project) (issue *gitlab.Issue, err error) {
	git, err := gitlab.NewClient(os.Getenv("GITLAB_TOKEN"))
	if err != nil {
		log.Panic().Err(err).Msg("Failed to create client")
	}

	issues, _, err := git.Issues.ListProjectIssues(project.ID, &gitlab.ListProjectIssuesOptions{
		Search: gitlab.Ptr(VulnerabilityIssueTitle),
		In:     gitlab.Ptr("title"),
	})
	if err != nil {
		log.Err(err).Msg("Failed to fetch current list of issues")
	}

	if len(issues) > 0 {
		issue = issues[0]
	}

	return
}

func CloseVulnerabilityIssue(project *gitlab.Project) {
	git, err := gitlab.NewClient(os.Getenv("GITLAB_TOKEN"))
	if err != nil {
		log.Panic().Err(err).Msg("Failed to create client")
	}

	issue, err := getVulnerabilityIssue(project)
	if err != nil {
		log.Err(err).Msg("Failed to fetch current list of issues")
		return
	}

	git.Issues.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
	})
	log.Info().Msg("Issue closed")
}

func OpenVulnerabilityIssue(project *gitlab.Project, report string) {
	git, err := gitlab.NewClient(os.Getenv("GITLAB_TOKEN"))
	if err != nil {
		log.Panic().Err(err).Msg("Failed to create gitlab client")
	}

	issue, err := getVulnerabilityIssue(project)
	if err != nil {
		log.Err(err).Msg("Failed to fetch current list of issues")
		return
	}

	if issue == nil {
		log.Error().Msg("Creating new issue")
		git.Issues.CreateIssue(project.ID, &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(VulnerabilityIssueTitle),
			Description: &report,
		})
	} else {
		log.Info().Msgf("Updating existing issue '%v'", issue.Title)
		git.Issues.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
			Description: &report,
			StateEvent:  gitlab.Ptr("reopen"),
		})
	}
}

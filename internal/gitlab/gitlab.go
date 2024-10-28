package gitlab

import (
	"errors"

	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
)

const VulnerabilityIssueTitle = "SecurityScanner - Vulnerability report"

type Service struct {
	client *gitlab.Client
}

func NewService(gitlabToken string) (*Service, error) {
	gitlabClient, err := gitlab.NewClient(gitlabToken)
	if err != nil {
		return nil, err
	}

	return &Service{
		client: gitlabClient,
	}, nil
}

func (s *Service) GetProjectList(namespace string) (projects []*gitlab.Project) {
	groups, _, err := s.client.Groups.ListGroups(&gitlab.ListGroupsOptions{
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
	projects, _, err = s.client.Groups.ListGroupProjects(group.ID,
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

func (s *Service) getVulnerabilityIssue(project *gitlab.Project) (issue *gitlab.Issue, err error) {
	issues, _, err := s.client.Issues.ListProjectIssues(project.ID, &gitlab.ListProjectIssuesOptions{
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

func (s *Service) CloseVulnerabilityIssue(project *gitlab.Project) (err error) {
	issue, err := s.getVulnerabilityIssue(project)
	if err != nil {
		return errors.Join(errors.New("failed to fetch current list of issues"), err)
	}

	if _, _, err = s.client.Issues.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
	}); err != nil {
		return errors.Join(errors.New("failed to update issue"), err)
	}

	log.Info().Msg("Issue closed")

	return
}

func (s *Service) OpenVulnerabilityIssue(project *gitlab.Project, report string) (err error) {
	issue, err := s.getVulnerabilityIssue(project)
	if err != nil {
		return errors.Join(errors.New("failed to fetch current list of issues"), err)
	}

	if issue == nil {
		log.Info().Msg("Creating new issue")

		if _, _, err = s.client.Issues.CreateIssue(project.ID, &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(VulnerabilityIssueTitle),
			Description: &report,
		}); err != nil {
			return errors.Join(errors.New("failed to create new issue"), err)
		}
	} else {
		log.Info().Msgf("Updating existing issue '%v'", issue.Title)

		if _, _, err = s.client.Issues.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
			Description: &report,
			StateEvent:  gitlab.Ptr("reopen"),
		}); err != nil {
			return errors.Join(errors.New("failed to update issue"), err)
		}

	}

	return
}

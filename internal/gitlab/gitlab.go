package gitlab

import (
	"errors"
	"fmt"
	"strings"

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

func (s *Service) getTopLevelGroup(groupPath string) (*gitlab.Group, error) {
	log.Info().Msgf("Getting top-level group %v", groupPath)
	groups, _, err := s.client.Groups.ListGroups(&gitlab.ListGroupsOptions{
		TopLevelOnly: gitlab.Ptr(true),
		Search:       gitlab.Ptr(groupPath),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to fetch list of groups like %v", groupPath), err)
	}

	for _, group := range groups {
		if group.Path == groupPath {
			return group, nil
		}
	}

	return nil, fmt.Errorf("group %v not found", groupPath)
}

// Function to get subgroups recursively
func (s *Service) getSubGroup(subGroupPaths []string, parent *gitlab.Group) (*gitlab.Group, error) {
	if len(subGroupPaths) == 0 {
		return parent, nil
	}
	subGroupPath := subGroupPaths[0]

	log.Info().Msgf("Getting subgroup %v of parent group %v", subGroupPaths[0], parent.Path)

	groups, _, err := s.client.Groups.ListSubGroups(parent.ID, &gitlab.ListSubGroupsOptions{
		Search: gitlab.Ptr(subGroupPath),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("error when search for group %v", subGroupPath), err)
	}

	var group *gitlab.Group
	for _, g := range groups {
		if g.Path == subGroupPath {
			group = g
		}
	}
	if group == nil {
		return nil, fmt.Errorf("group %v not found in parent %v", subGroupPath, parent.Path)
	}

	log.Info().Msgf("Found subgroup %v of parent group %v", group.Path, parent.Path)

	return s.getSubGroup(subGroupPaths[1:], group)
}

func (s *Service) GetProjectList(groupPath []string) (projects []*gitlab.Project, err error) {
	topGroup, err := s.getTopLevelGroup(groupPath[0])
	if err != nil {
		return nil, err
	}

	group, err := s.getSubGroup(groupPath[1:], topGroup)
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("Fetching projects for group '%v'", group.Path)
	projects, _, err = s.client.Groups.ListGroupProjects(group.ID,
		&gitlab.ListGroupProjectsOptions{
			Archived:         gitlab.Ptr(false),
			Simple:           gitlab.Ptr(true),
			IncludeSubGroups: gitlab.Ptr(true),
			WithShared:       gitlab.Ptr(false),
		})
	if err != nil {
		log.Panic().Err(err).Msg("Failed to fetch list of projects")
	}

	var ps []string
	for _, project := range projects {
		ps = append(ps, project.PathWithNamespace)
	}
	log.Info().Msgf("Projects to scan: [\n\t%v\n]", strings.Join(ps, "\n\t"))

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

func (s *Service) OpenVulnerabilityIssue(project *gitlab.Project, report string) (issue *gitlab.Issue, err error) {
	issue, err = s.getVulnerabilityIssue(project)
	if err != nil {
		return nil, errors.Join(errors.New("failed to fetch current list of issues"), err)
	}

	if issue == nil {
		log.Info().Msg("Creating new issue")

		issue, _, err = s.client.Issues.CreateIssue(project.ID, &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(VulnerabilityIssueTitle),
			Description: &report,
		})
		if err != nil {
			return nil, errors.Join(errors.New("failed to create new issue"), err)
		}

		return
	}

	log.Info().Msgf("Updating existing issue '%v'", issue.Title)

	issue, _, err = s.client.Issues.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
		Description: &report,
		StateEvent:  gitlab.Ptr("reopen"),
	})
	if err != nil {
		return nil, errors.Join(errors.New("failed to update issue"), err)
	}

	return
}

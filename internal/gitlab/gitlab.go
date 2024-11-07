package gitlab

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
)

const VulnerabilityIssueTitle = "SecurityScanner - Vulnerability report"

type IService interface {
	GetProjectList(groupPath []string) ([]*gitlab.Project, error)
	CloseVulnerabilityIssue(project *gitlab.Project) error
	OpenVulnerabilityIssue(project *gitlab.Project, report string) (*gitlab.Issue, error)
}

type service struct {
	client iclient
}

func New(gitlabToken string) (IService, error) {
	gitlabClient, err := gitlab.NewClient(gitlabToken)
	if err != nil {
		return nil, err
	}

	s := service{&client{client: gitlabClient}}

	return &s, nil
}

func (s *service) getTopLevelGroup(groupPath string) (*gitlab.Group, error) {
	log.Info().Msgf("Getting top-level group %v", groupPath)
	groups, _, err := s.client.ListGroups(&gitlab.ListGroupsOptions{
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
func (s *service) getSubGroup(subGroupPaths []string, parent *gitlab.Group) (*gitlab.Group, error) {
	if len(subGroupPaths) == 0 {
		return parent, nil
	}
	subGroupPath := subGroupPaths[0]

	log.Info().Msgf("Getting subgroup %v of parent group %v", subGroupPaths[0], parent.Path)

	groups, _, err := s.client.ListSubGroups(parent.ID, &gitlab.ListSubGroupsOptions{
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

func (s *service) GetProjectList(groupPath []string) (projects []*gitlab.Project, err error) {
	topGroup, err := s.getTopLevelGroup(groupPath[0])
	if err != nil {
		return nil, err
	}

	group, err := s.getSubGroup(groupPath[1:], topGroup)
	if err != nil {
		return nil, err
	}

	log.Info().Msgf("Fetching projects for group '%v'", group.Path)
	projects, err = s.listGroupProjects(group.ID)
	if err != nil {
		return nil, err
	}

	var ps []string
	for _, project := range projects {
		ps = append(ps, project.PathWithNamespace)
	}
	log.Info().Msgf("Projects to scan: [\n\t%v\n]", strings.Join(ps, "\n\t"))

	return
}

func (s *service) getVulnerabilityIssue(project *gitlab.Project) (issue *gitlab.Issue, err error) {
	issues, _, err := s.client.ListProjectIssues(project.ID, &gitlab.ListProjectIssuesOptions{
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

func (s *service) CloseVulnerabilityIssue(project *gitlab.Project) (err error) {
	issue, err := s.getVulnerabilityIssue(project)
	if err != nil {
		return errors.Join(errors.New("failed to fetch current list of issues"), err)
	}

	if issue == nil {
		log.Info().Msgf("[%v] No issue to close, nothing to do", project.Name)
		return
	}

	if issue.State == "closed" {
		log.Info().Msg("Issue already closed")
		return
	}

	if issue, _, err = s.client.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
	}); err != nil {
		return errors.Join(errors.New("failed to update issue"), err)
	}

	if issue.State != "closed" {
		return errors.New("failed to close issue")
	}

	log.Info().Msgf("[%v] Issue closed", project.Name)

	return
}

func (s *service) OpenVulnerabilityIssue(project *gitlab.Project, report string) (issue *gitlab.Issue, err error) {
	issue, err = s.getVulnerabilityIssue(project)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("[%v] Failed to fetch current list of issues", project.Name), err)
	}

	if issue == nil {
		log.Info().Msgf("[%v] Creating new issue", project.Name)

		issue, _, err = s.client.CreateIssue(project.ID, &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(VulnerabilityIssueTitle),
			Description: &report,
		})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("[%v] failed to create new issue", project.Name), err)
		}

		return
	}

	log.Info().Msgf("[%v] Updating existing issue '%v'", project.Name, issue.Title)

	issue, _, err = s.client.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
		Description: &report,
		StateEvent:  gitlab.Ptr("reopen"),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("[%v] Failed to update issue", project.Name), err)
	}

	return
}

func (s *service) listGroupProjects(groupID int) (projects []*gitlab.Project, err error) {
	projects, response, err := s.client.ListGroupProjects(groupID,
		&gitlab.ListGroupProjectsOptions{
			Archived:         gitlab.Ptr(false),
			Simple:           gitlab.Ptr(true),
			IncludeSubGroups: gitlab.Ptr(true),
			WithShared:       gitlab.Ptr(false),
			ListOptions: gitlab.ListOptions{
				Page: 1,
			},
		})
	if err != nil {
		return nil, errors.Join(errors.New("failed to fetch list of projects"), err)
	}

	if response.TotalPages > 1 {
		nextProjects, err := s.listGroupNextProjects(groupID, response.TotalPages)
		if err != nil {
			return nil, err
		}

		projects = append(projects, nextProjects...)
	}

	return
}

func (s *service) listGroupNextProjects(groupID int, totalPages int) (projects []*gitlab.Project, err error) {
	var wg sync.WaitGroup
	nextProjectsChan := make(chan []*gitlab.Project, totalPages)
	for p := 2; p <= totalPages; p++ {
		wg.Add(1)

		go func(reportsChan chan<- []*gitlab.Project) {
			log.Info().Int("groupID", groupID).Int("page", p).Msg("Fetching projects of next page")
			projects, _, err := s.client.ListGroupProjects(groupID,
				&gitlab.ListGroupProjectsOptions{
					Archived:         gitlab.Ptr(false),
					Simple:           gitlab.Ptr(true),
					IncludeSubGroups: gitlab.Ptr(true),
					WithShared:       gitlab.Ptr(false),
					ListOptions: gitlab.ListOptions{
						Page: p,
					},
				})
			if err != nil {
				log.Err(err).Int("groupID", groupID).Int("page", p).Msg("Failed to fetch projects of next page, these projects will be missing.")
			}

			nextProjectsChan <- projects
			defer wg.Done()
		}(nextProjectsChan)
	}
	wg.Wait()
	close(nextProjectsChan)

	// Collect projects
	for nextProjects := range nextProjectsChan {
		projects = append(projects, nextProjects...)
	}

	return
}

package gitlab

import (
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
)

const VulnerabilityIssueTitle = "Sheriff - 🚨 Vulnerability report"

// IService is the interface of the GitLab service as needed by sheriff
type IService interface {
	GetProjectList(groupPath string) ([]*gitlab.Project, error)
	CloseVulnerabilityIssue(project *gitlab.Project) error
	OpenVulnerabilityIssue(project *gitlab.Project, report string) (*gitlab.Issue, error)
}

type service struct {
	client iclient
}

// New creates a new GitLab service
func New(gitlabToken string) (IService, error) {
	gitlabClient, err := gitlab.NewClient(gitlabToken)
	if err != nil {
		return nil, err
	}

	s := service{&client{client: gitlabClient}}

	return &s, nil
}

// GetProjectList returns the list of projects for the given GitLab group path
func (s *service) GetProjectList(groupPath string) (projects []*gitlab.Project, err error) {
	group, err := s.getGroup(groupPath)
	if err != nil {
		return nil, err
	}

	log.Info().Str("group", group.Path).Msg("Group found")
	projects, err = s.listGroupProjects(group.ID)
	if err != nil {
		return nil, err
	}

	var ps []string
	for _, project := range projects {
		ps = append(ps, project.PathWithNamespace)
	}
	log.Info().Strs("projects", ps).Msg("Projects to scan")

	return
}

// CloseVulnerabilityIssue closes the vulnerability issue for the given project
func (s *service) CloseVulnerabilityIssue(project *gitlab.Project) (err error) {
	issue, err := s.getVulnerabilityIssue(project)
	if err != nil {
		return errors.Join(errors.New("failed to fetch current list of issues"), err)
	}

	if issue == nil {
		log.Info().Str("project", project.Name).Msg("No issue to close, nothing to do")
		return
	}

	if issue.State == "closed" {
		log.Info().Str("project", project.Name).Msg("Issue already closed")
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

	log.Info().Str("project", project.Name).Msg("Issue closed")

	return
}

func (s *service) getGroup(groupPath string) (*gitlab.Group, error) {
	log.Info().Str("group", groupPath).Msg("Getting group")
	groups, _, err := s.client.ListGroups(&gitlab.ListGroupsOptions{
		Search: gitlab.Ptr(groupPath),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to fetch list of groups like %v", groupPath), err)
	}

	for _, group := range groups {
		if group.FullPath == groupPath {
			return group, nil
		}
	}

	return nil, fmt.Errorf("group %v not found", groupPath)
}

// OpenVulnerabilityIssue opens or updates the vulnerability issue for the given project
func (s *service) OpenVulnerabilityIssue(project *gitlab.Project, report string) (issue *gitlab.Issue, err error) {
	issue, err = s.getVulnerabilityIssue(project)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("[%v] Failed to fetch current list of issues", project.Name), err)
	}

	if issue == nil {
		log.Info().Str("project", project.Name).Msg("Creating new issue")

		issue, _, err = s.client.CreateIssue(project.ID, &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(VulnerabilityIssueTitle),
			Description: &report,
		})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("[%v] failed to create new issue", project.Name), err)
		}

		return
	}

	log.Info().Str("project", project.Name).Str("issue", issue.Title).Msg("Updating existing issue")

	issue, _, err = s.client.UpdateIssue(project.ID, issue.IID, &gitlab.UpdateIssueOptions{
		Description: &report,
		StateEvent:  gitlab.Ptr("reopen"),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("[%v] Failed to update issue", project.Name), err)
	}

	return
}

// getVulnerabilityIssue returns the vulnerability issue for the given project
func (s *service) getVulnerabilityIssue(project *gitlab.Project) (issue *gitlab.Issue, err error) {
	issues, _, err := s.client.ListProjectIssues(project.ID, &gitlab.ListProjectIssuesOptions{
		Search: gitlab.Ptr(VulnerabilityIssueTitle),
		In:     gitlab.Ptr("title"),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch current list of issues")
	}

	if len(issues) > 0 {
		issue = issues[0]
	}

	return
}

// listGroupProjects returns the list of projects for the given group ID
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

// listGroupNextProjects returns the list of projects for the given group ID from the next pages
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
				log.Error().Err(err).Int("groupID", groupID).Int("page", p).Msg("Failed to fetch projects of next page, these projects will be missing.")
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

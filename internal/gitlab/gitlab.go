package gitlab

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
)

const VulnerabilityIssueTitle = "Sheriff - 🚨 Vulnerability report"

// IService is the interface of the GitLab service as needed by sheriff
type IService interface {
	GetProjectList(groupPaths []string, projectPaths []string) (projects []gitlab.Project, warn error)
	CloseVulnerabilityIssue(project gitlab.Project) error
	OpenVulnerabilityIssue(project gitlab.Project, report string) (*gitlab.Issue, error)
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

func (s *service) GetProjectList(groupPaths []string, projectPaths []string) (projects []gitlab.Project, warn error) {
	projects, pwarn := s.gatherProjects(projectPaths)
	if pwarn != nil {
		pwarn = errors.Join(errors.New("errors occured when gathering projects"), pwarn)
		warn = errors.Join(pwarn, warn)
	}

	groupsProjects, gpwarn := s.gatherGroupsProjects(groupPaths)
	if gpwarn != nil {
		gpwarn = errors.Join(errors.New("errors occured when gathering groups projects"), gpwarn)
		warn = errors.Join(gpwarn, warn)
	}

	projects = append(projects, groupsProjects...)

	// Filter unique projects -- there may be duplicates between groups, other groups and projects
	projects = filterUniqueProjects(projects)

	projectsNamespaces := pie.Map(projects, func(p gitlab.Project) string { return p.PathWithNamespace })
	log.Info().Strs("projects", projectsNamespaces).Msg("Projects to scan")

	return projects, warn
}

// CloseVulnerabilityIssue closes the vulnerability issue for the given project
func (s *service) CloseVulnerabilityIssue(project gitlab.Project) (err error) {
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

// OpenVulnerabilityIssue opens or updates the vulnerability issue for the given project
func (s *service) OpenVulnerabilityIssue(project gitlab.Project, report string) (issue *gitlab.Issue, err error) {
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

func (s *service) getProject(path string) (*gitlab.Project, error) {
	log.Info().Str("path", path).Msg("Getting project")

	lastSlash := strings.LastIndex(path, "/")

	if lastSlash == -1 {
		return nil, fmt.Errorf("invalid project path %v", path)
	}

	groupPath := path[:lastSlash]

	group, err := s.getGroup(groupPath)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to fetch group %v", groupPath), err)
	}

	projects, _, lgerr := s.listGroupProjects(group.ID)
	if lgerr != nil {
		return nil, errors.Join(fmt.Errorf("failed to fetch list of projects like %v", path), err)
	}
	for _, project := range projects {
		if project.PathWithNamespace == path {
			return &project, nil
		}
	}

	return nil, fmt.Errorf("project %v not found", path)
}

func (s *service) gatherGroupsProjects(groupPaths []string) (projects []gitlab.Project, warn error) {
	for _, groupPath := range groupPaths {
		group, gerr := s.getGroup(groupPath)
		if gerr != nil {
			log.Error().Err(gerr).Str("group", groupPath).Msg("Failed to fetch group")
			gerr = errors.Join(fmt.Errorf("failed to fetch group %v", groupPath), gerr)
			warn = errors.Join(gerr, warn)
			continue
		}

		if groupProjects, gpwarn, gperr := s.listGroupProjects(group.ID); gperr != nil {
			log.Error().Err(gpwarn).Str("group", groupPath).Msg("Failed to fetch projects of group")
			gperr = errors.Join(fmt.Errorf("failed to fetch projects of group %v", groupPath), gperr)
			warn = errors.Join(gperr, warn)
		} else if gpwarn != nil {
			gpwarn = errors.Join(fmt.Errorf("failed to fetch projects of group %v", groupPath), gpwarn)
			warn = errors.Join(gpwarn, warn)

			projects = append(projects, groupProjects...)
		} else {
			projects = append(projects, groupProjects...)
		}
	}

	return
}

func (s *service) gatherProjects(projectPaths []string) (projects []gitlab.Project, warn error) {
	for _, projectPath := range projectPaths {
		log.Info().Str("project", projectPath).Msg("Getting project")
		p, err := s.getProject(projectPath)
		if err != nil {
			log.Error().Err(err).Str("project", projectPath).Msg("Failed to fetch project")
			err = errors.Join(fmt.Errorf("failed to fetch project %v", projectPath), err)
			warn = errors.Join(err, warn)
			continue
		}

		projects = append(projects, *p)
	}

	return
}

// getVulnerabilityIssue returns the vulnerability issue for the given project
func (s *service) getVulnerabilityIssue(project gitlab.Project) (issue *gitlab.Issue, err error) {
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
func (s *service) listGroupProjects(groupID int) (projects []gitlab.Project, warn error, err error) {
	projectPtrs, response, err := s.client.ListGroupProjects(groupID,
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
		return nil, nil, errors.Join(errors.New("failed to fetch list of projects"), err)
	}

	projects, errCount := dereferenceProjectsPointers(projectPtrs)
	if errCount > 0 {
		log.Warn().Int("groupID", groupID).Int("count", errCount).Msg("Found nil projects, skipping them.")
	}

	if response.TotalPages > 1 {
		nextProjects, lgwarn := s.listGroupNextProjects(groupID, response.TotalPages)
		if lgwarn != nil {
			lgwarn = errors.Join(errors.New("errors occured when fetching next pages"), lgwarn)
			warn = errors.Join(lgwarn, warn)
		}

		projects = append(projects, nextProjects...)
	}

	return
}

func ToChan[T any](s []T) <-chan T {
	ch := make(chan T, len(s))
	for _, e := range s {
		ch <- e
	}
	close(ch)
	return ch
}

// listGroupNextProjects returns the list of projects for the given group ID from the next pages
func (s *service) listGroupNextProjects(groupID int, totalPages int) (projects []gitlab.Project, warn error) {
	var wg sync.WaitGroup
	nextProjectsChan := make(chan []gitlab.Project, totalPages)
	warnChan := make(chan error, totalPages)
	for p := 2; p <= totalPages; p++ {
		wg.Add(1)

		go func(reportsChan chan<- []gitlab.Project) {
			defer wg.Done()
			log.Info().Int("groupID", groupID).Int("page", p).Msg("Fetching projects of next page")
			projectPtrs, _, err := s.client.ListGroupProjects(groupID,
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
				warnChan <- err
			}

			projects, errCount := dereferenceProjectsPointers(projectPtrs)
			if errCount > 0 {
				log.Warn().Int("groupID", groupID).Int("page", p).Int("count", errCount).Msg("Found nil projects, skipping them.")
			}

			nextProjectsChan <- projects
		}(nextProjectsChan)
	}
	wg.Wait()
	close(nextProjectsChan)
	close(warnChan)

	// Collect projects
	for nextProjects := range nextProjectsChan {
		projects = append(projects, nextProjects...)
	}

	// Collect warnings
	for w := range warnChan {
		warn = errors.Join(w, warn)
	}

	return
}

func filterUniqueProjects(projects []gitlab.Project) (filteredProjects []gitlab.Project) {
	projectsNamespaces := make(map[int]bool)

	for _, project := range projects {
		if _, ok := projectsNamespaces[project.ID]; !ok {
			projectsNamespaces[project.ID] = true
			filteredProjects = append(filteredProjects, project)
		}
	}

	return
}

func dereferenceProjectsPointers(projects []*gitlab.Project) (filteredProjects []gitlab.Project, errCount int) {
	for _, project := range projects {
		if project == nil {
			errCount++
			continue
		}
		filteredProjects = append(filteredProjects, *project)
	}

	return
}

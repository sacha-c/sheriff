// This client is a thin wrapper around the go-gitlab library. It provides an interface to the GitLab client
// The main purpose of this client is to provide an interface to the GitLab client which can be mocked in tests.
// As such this MUST be as thin as possible and MUST not contain any business logic, since it is not testable.
package gitlab

import (
	"github.com/xanzy/go-gitlab"
)

type IClient interface {
	ListGroups(opt *gitlab.ListGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error)
	ListSubGroups(groupId int, opt *gitlab.ListSubGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error)
	ListGroupProjects(groupId int, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error)
	ListProjectIssues(projectId interface{}, opt *gitlab.ListProjectIssuesOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Issue, *gitlab.Response, error)
	CreateIssue(projectId interface{}, opt *gitlab.CreateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error)
	UpdateIssue(projectId interface{}, issueId int, opt *gitlab.UpdateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error)
}

type Client struct {
	client *gitlab.Client
}

func (c *Client) ListGroups(opt *gitlab.ListGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error) {
	return c.client.Groups.ListGroups(opt, options...)
}

func (c *Client) ListSubGroups(groupId int, opt *gitlab.ListSubGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error) {
	return c.client.Groups.ListSubGroups(groupId, opt, options...)
}

func (c *Client) ListGroupProjects(groupId int, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error) {
	return c.client.Groups.ListGroupProjects(groupId, opt, options...)
}

func (c *Client) ListProjectIssues(projectId interface{}, opt *gitlab.ListProjectIssuesOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Issue, *gitlab.Response, error) {
	return c.client.Issues.ListProjectIssues(projectId, opt, options...)
}

func (c *Client) CreateIssue(projectId interface{}, opt *gitlab.CreateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	return c.client.Issues.CreateIssue(projectId, opt, options...)
}

func (c *Client) UpdateIssue(projectId interface{}, issueId int, opt *gitlab.UpdateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	return c.client.Issues.UpdateIssue(projectId, issueId, opt, options...)
}

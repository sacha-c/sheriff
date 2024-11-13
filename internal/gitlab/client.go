// Package gitlab provides a GitLab service to interact with the GitLab API.
package gitlab

// This client is a thin wrapper around the go-gitlab library. It provides an interface to the GitLab client
// The main purpose of this client is to provide an interface to the GitLab client which can be mocked in tests.
// As such this MUST be as thin as possible and MUST not contain any business logic, since it is not testable.

import (
	"github.com/xanzy/go-gitlab"
)

type iclient interface {
	ListGroups(opt *gitlab.ListGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error)
	ListGroupProjects(groupId int, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error)
	ListProjectIssues(projectId interface{}, opt *gitlab.ListProjectIssuesOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Issue, *gitlab.Response, error)
	CreateIssue(projectId interface{}, opt *gitlab.CreateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error)
	UpdateIssue(projectId interface{}, issueId int, opt *gitlab.UpdateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error)
}

type client struct {
	client *gitlab.Client
}

func (c *client) ListGroups(opt *gitlab.ListGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error) {
	return c.client.Groups.ListGroups(opt, options...)
}

func (c *client) ListGroupProjects(groupId int, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error) {
	return c.client.Groups.ListGroupProjects(groupId, opt, options...)
}

func (c *client) ListProjectIssues(projectId interface{}, opt *gitlab.ListProjectIssuesOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Issue, *gitlab.Response, error) {
	return c.client.Issues.ListProjectIssues(projectId, opt, options...)
}

func (c *client) CreateIssue(projectId interface{}, opt *gitlab.CreateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	return c.client.Issues.CreateIssue(projectId, opt, options...)
}

func (c *client) UpdateIssue(projectId interface{}, issueId int, opt *gitlab.UpdateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	return c.client.Issues.UpdateIssue(projectId, issueId, opt, options...)
}

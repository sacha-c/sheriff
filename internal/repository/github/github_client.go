// Package gitlab provides a GitLab service to interact with the GitLab API.
package github

import (
	"context"

	"github.com/google/go-github/v68/github"
)

// This client is a thin wrapper around the go-github library. It provides an interface to the GitHub client
// The main purpose of this client is to provide an interface to the GitHub client which can be mocked in tests.
// As such this MUST be as thin as possible and MUST not contain any business logic, since it is not testable.

type iGithubClient interface {
	GetRepository(owner string, repo string) (*github.Repository, *github.Response, error)
	GetOrganizationRepositories(org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error)
	GetUserRepositories(user string, opts *github.RepositoryListByUserOptions) ([]*github.Repository, *github.Response, error)
}

type githubClient struct {
	client *github.Client
}

func (c *githubClient) GetRepository(owner string, repo string) (*github.Repository, *github.Response, error) {
	return c.client.Repositories.Get(context.Background(), owner, repo)
}

func (c *githubClient) GetOrganizationRepositories(org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error) {
	return c.client.Repositories.ListByOrg(context.Background(), org, opts)
}

func (c *githubClient) GetUserRepositories(user string, opts *github.RepositoryListByUserOptions) ([]*github.Repository, *github.Response, error) {
	return c.client.Repositories.ListByUser(context.Background(), user, opts)
}

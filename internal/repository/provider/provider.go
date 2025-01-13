package provider

import (
	"errors"
	"fmt"
	"sheriff/internal/repository"
	"sheriff/internal/repository/github"
	"sheriff/internal/repository/gitlab"
)

// IProvider is the interface of the repository service as needed by sheriff
type IProvider interface {
	Provide(repository.RepositoryType) repository.IRepositoryService
}

type provider struct {
	gitlabService repository.IRepositoryService
	githubService repository.IRepositoryService
}

func NewProvider(gitlabToken string, githubToken string) (IProvider, error) {
	gitlabService, err := gitlab.New(gitlabToken)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to create gitlab provider"), err)
	}

	githubService := github.New(githubToken)

	return provider{
		gitlabService: gitlabService,
		githubService: githubService,
	}, nil
}

func (s provider) Provide(p repository.RepositoryType) repository.IRepositoryService {
	if p == repository.Gitlab {
		return s.gitlabService
	} else {
		return s.githubService
	}
}

package github

import (
	"errors"
	"testing"

	"github.com/google/go-github/v68/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewService(t *testing.T) {
	s, err := New("token")

	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestGetProjectListOrganizationRepos(t *testing.T) {
	mockService := mockService{}
	mockService.On("GetOrganizationRepositories", "org", mock.Anything).Return([]*github.Repository{{Name: github.Ptr("Hello World")}}, &github.Response{}, nil)

	svc := githubService{client: &mockService}

	projects, err := svc.GetProjectList([]string{"org"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockService.AssertExpectations(t)
}

func TestGetProjectListUserRepos(t *testing.T) {
	mockService := mockService{}
	mockService.On("GetOrganizationRepositories", "user", mock.Anything).Return([]*github.Repository{}, &github.Response{}, errors.New("error"))
	mockService.On("GetUserRepositories", "user", mock.Anything).Return([]*github.Repository{{Name: github.Ptr("Hello World")}}, &github.Response{}, nil)

	svc := githubService{client: &mockService}

	projects, err := svc.GetProjectList([]string{"user"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockService.AssertExpectations(t)
}

func TestGetProjectSpecificRepo(t *testing.T) {
	mockService := mockService{}
	mockService.On("GetRepository", "owner", "repo").Return(&github.Repository{Name: github.Ptr("Hello World")}, &github.Response{}, nil)

	svc := githubService{client: &mockService}

	projects, err := svc.GetProjectList([]string{"owner/repo"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockService.AssertExpectations(t)
}

func TestGetProjectListWithNextPage(t *testing.T) {
	project1 := &github.Repository{ID: github.Ptr(int64(1))}
	project2 := &github.Repository{ID: github.Ptr(int64(2))}

	mockService := mockService{}
	mockService.On("GetOrganizationRepositories", "org", &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	}, mock.Anything).Return([]*github.Repository{project1}, &github.Response{NextPage: 2}, nil)
	mockService.On("GetOrganizationRepositories", "org", &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    2,
			PerPage: 100,
		},
	}, mock.Anything).Return([]*github.Repository{project2}, &github.Response{NextPage: 0}, nil)

	svc := githubService{client: &mockService}

	projects, err := svc.GetProjectList([]string{"org"})

	assert.Nil(t, err)
	assert.Len(t, projects, 2)
	assert.Equal(t, int(*project1.ID), projects[0].ID)
	assert.Equal(t, int(*project2.ID), projects[1].ID)
	mockService.AssertExpectations(t)
}

type mockService struct {
	mock.Mock
}

func (c *mockService) GetRepository(owner string, repo string) (*github.Repository, *github.Response, error) {
	args := c.Called(owner, repo)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).(*github.Repository), r, args.Error(2)
}

func (c *mockService) GetOrganizationRepositories(org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error) {
	args := c.Called(org, opts)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).([]*github.Repository), r, args.Error(2)
}

func (c *mockService) GetUserRepositories(user string, opts *github.RepositoryListByUserOptions) ([]*github.Repository, *github.Response, error) {
	args := c.Called(user, opts)
	var r *github.Response
	if resp := args.Get(1); resp != nil {
		r = args.Get(1).(*github.Response)
	}
	return args.Get(0).([]*github.Repository), r, args.Error(2)
}

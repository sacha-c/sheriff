package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xanzy/go-gitlab"
)

func TestNewService(t *testing.T) {
	s, err := NewService("token")

	assert.Nil(t, err)
	assert.NotNil(t, s)
	assert.NotNil(t, s.client)
}

func TestGetProjectListWithTopLevelGroup(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListGroups", mock.Anything, mock.Anything).Return([]*gitlab.Group{{ID: 1, Path: "group"}}, nil, nil)
	mockClient.On("ListGroupProjects", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Project{{Name: "Hello World"}}, nil, nil)

	svc := newService(&mockClient)

	projects, err := svc.GetProjectList([]string{"group"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockClient.AssertExpectations(t)
}

func TestGetProjectListWithSubGroup(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListGroups", mock.Anything, mock.Anything).Return([]*gitlab.Group{{ID: 1, Path: "group"}}, nil, nil)
	mockClient.On("ListSubGroups", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Group{{ID: 2, Path: "subgroup"}}, nil, nil)
	mockClient.On("ListGroupProjects", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Project{{Name: "Hello World"}}, nil, nil)

	svc := newService(&mockClient)

	projects, err := svc.GetProjectList([]string{"group", "subgroup"})

	assert.Nil(t, err)
	assert.NotEmpty(t, projects)
	assert.Equal(t, "Hello World", projects[0].Name)
	mockClient.AssertExpectations(t)
}

func TestCloseVulnerabilityIssue(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{{State: "opened"}}, nil, nil)
	mockClient.On("UpdateIssue", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{State: "closed"}, nil, nil)

	svc := newService(&mockClient)

	err := svc.CloseVulnerabilityIssue(&gitlab.Project{})

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestCloseVulnerabilityIssueAlreadyClosed(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{{State: "closed"}}, nil, nil)

	svc := newService(&mockClient)

	err := svc.CloseVulnerabilityIssue(&gitlab.Project{})

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestCloseVulnerabilityIssueNoIssue(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{}, nil, nil)

	svc := newService(&mockClient)

	err := svc.CloseVulnerabilityIssue(&gitlab.Project{})

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestOpenVulnerabilityIssue(t *testing.T) {
	mockClient := mockClient{}
	mockClient.On("ListProjectIssues", mock.Anything, mock.Anything, mock.Anything).Return([]*gitlab.Issue{}, nil, nil)
	mockClient.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{ID: 666}, nil, nil)

	svc := newService(&mockClient)

	i, err := svc.OpenVulnerabilityIssue(&gitlab.Project{}, "report")
	assert.Nil(t, err)
	assert.NotNil(t, i)
	assert.Equal(t, 666, i.ID)
}

type mockClient struct {
	mock.Mock
}

func (c *mockClient) ListGroups(opt *gitlab.ListGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error) {
	args := c.Called(opt, options)
	return args.Get(0).([]*gitlab.Group), nil, args.Error(2)
}

func (c *mockClient) ListSubGroups(groupId int, opt *gitlab.ListSubGroupsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Group, *gitlab.Response, error) {
	args := c.Called(groupId, opt, options)
	return args.Get(0).([]*gitlab.Group), nil, args.Error(2)
}

func (c *mockClient) ListGroupProjects(groupId int, opt *gitlab.ListGroupProjectsOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Project, *gitlab.Response, error) {
	args := c.Called(groupId, opt, options)
	return args.Get(0).([]*gitlab.Project), nil, args.Error(2)
}

func (c *mockClient) ListProjectIssues(projectId interface{}, opt *gitlab.ListProjectIssuesOptions, options ...gitlab.RequestOptionFunc) ([]*gitlab.Issue, *gitlab.Response, error) {
	args := c.Called(projectId, opt, options)
	return args.Get(0).([]*gitlab.Issue), nil, args.Error(2)
}

func (c *mockClient) CreateIssue(projectId interface{}, opt *gitlab.CreateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	args := c.Called(projectId, opt, options)
	return args.Get(0).(*gitlab.Issue), nil, args.Error(2)
}

func (c *mockClient) UpdateIssue(projectId interface{}, issueId int, opt *gitlab.UpdateIssueOptions, options ...gitlab.RequestOptionFunc) (*gitlab.Issue, *gitlab.Response, error) {
	args := c.Called(projectId, issueId, opt, options)
	return args.Get(0).(*gitlab.Issue), nil, args.Error(2)
}

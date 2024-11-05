package scan

import (
	"securityscanner/internal/osv"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xanzy/go-gitlab"
)

func TestNewService(t *testing.T) {
	s := NewService(&mockGitlabService{}, &mockSlackService{}, &mockGitService{}, &mockOSVService{})

	assert.NotNil(t, s)
}

func TestScanNoProjects(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("GetProjectList", []string{"group", "to", "scan"}).Return([]*gitlab.Project{}, nil)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return(nil)

	mockGitService := &mockGitService{}
	mockGitService.On("Clone", mock.Anything, "https://gitlab.com/group/to/scan.git").Return(nil)

	mockOSVService := &mockOSVService{}
	mockOSVService.On("Scan", mock.Anything).Return(&osv.Report{}, nil)

	svc := NewService(mockGitlabService, mockSlackService, mockGitService, mockOSVService)

	err := svc.Scan("group/to/scan", true, "channel", false, false)

	assert.Nil(t, err)
	mockGitlabService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestScanNonVulnerableProject(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("GetProjectList", []string{"group", "to", "scan"}).Return([]*gitlab.Project{{Name: "Hello World", HTTPURLToRepo: "https://gitlab.com/group/to/scan.git"}}, nil)
	mockGitlabService.On("CloseVulnerabilityIssue", mock.Anything).Return(nil)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return(nil)

	mockGitService := &mockGitService{}
	mockGitService.On("Clone", mock.Anything, "https://gitlab.com/group/to/scan.git").Return(nil)

	mockOSVService := &mockOSVService{}
	mockOSVService.On("Scan", mock.Anything).Return(&osv.Report{}, nil)

	svc := NewService(mockGitlabService, mockSlackService, mockGitService, mockOSVService)

	err := svc.Scan("group/to/scan", true, "channel", false, false)

	assert.Nil(t, err)
	mockGitlabService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

func TestScanVulnerableProject(t *testing.T) {
	mockGitlabService := &mockGitlabService{}
	mockGitlabService.On("GetProjectList", []string{"group", "to", "scan"}).Return([]*gitlab.Project{{Name: "Hello World", HTTPURLToRepo: "https://gitlab.com/group/to/scan.git"}}, nil)
	mockGitlabService.On("OpenVulnerabilityIssue", mock.Anything, mock.Anything).Return(&gitlab.Issue{}, nil)

	mockSlackService := &mockSlackService{}
	mockSlackService.On("PostMessage", "channel", mock.Anything).Return(nil)

	mockGitService := &mockGitService{}
	mockGitService.On("Clone", mock.Anything, "https://gitlab.com/group/to/scan.git").Return(nil)

	mockOSVService := &mockOSVService{}
	report := &osv.Report{
		Results: []osv.Result{
			{
				Packages: []osv.Package{
					{
						Vulnerabilities: []osv.Vulnerability{
							{
								Id: "CVE-2021-1234",
							},
						},
					},
				},
			},
		},
	}
	mockOSVService.On("Scan", mock.Anything).Return(report, nil)

	svc := NewService(mockGitlabService, mockSlackService, mockGitService, mockOSVService)

	err := svc.Scan("group/to/scan", true, "channel", false, false)

	assert.Nil(t, err)
	mockGitlabService.AssertExpectations(t)
	mockSlackService.AssertExpectations(t)
}

type mockGitlabService struct {
	mock.Mock
}

func (c *mockGitlabService) GetProjectList(groupPath []string) ([]*gitlab.Project, error) {
	args := c.Called(groupPath)
	return args.Get(0).([]*gitlab.Project), args.Error(1)
}

func (c *mockGitlabService) CloseVulnerabilityIssue(project *gitlab.Project) error {
	args := c.Called(project)
	return args.Error(0)
}

func (c *mockGitlabService) OpenVulnerabilityIssue(project *gitlab.Project, report string) (*gitlab.Issue, error) {
	args := c.Called(project, report)
	return args.Get(0).(*gitlab.Issue), args.Error(1)
}

type mockSlackService struct {
	mock.Mock
}

func (c *mockSlackService) PostMessage(channelName string, options ...slack.MsgOption) error {
	args := c.Called(channelName, options)
	return args.Error(0)
}

type mockGitService struct {
	mock.Mock
}

func (c *mockGitService) Clone(dir string, url string) (err error) {
	args := c.Called(dir, url)
	return args.Error(0)
}

type mockOSVService struct {
	mock.Mock
}

func (c *mockOSVService) Scan(dir string) (*osv.Report, error) {
	args := c.Called(dir)
	return args.Get(0).(*osv.Report), args.Error(1)
}

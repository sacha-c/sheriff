package git

import (
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewService(t *testing.T) {
	s := New("token")

	assert.NotNil(t, s)
}

func TestClone(t *testing.T) {
	path := "path/to/directory"
	url := "https://gitlab.com/username/repo.git"
	token := "token"

	mockGit := &mockGit{}
	mockGit.On("PlainClone", path, false, &git.CloneOptions{
		URL: url,
		Auth: &http.BasicAuth{
			Username: "N/A",
			Password: token,
		},
		Depth: 1,
	}).Return(&git.Repository{}, nil)

	s := &service{client: mockGit, token: token}

	err := s.Clone(path, url)

	assert.Nil(t, err)
	mockGit.AssertExpectations(t)
}

type mockGit struct {
	mock.Mock
}

func (g *mockGit) PlainClone(path string, isBare bool, o *git.CloneOptions) (*git.Repository, error) {
	args := g.Called(path, isBare, o)
	return args.Get(0).(*git.Repository), args.Error(1)
}

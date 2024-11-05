package git

import (
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

type IService interface {
	Clone(dir string, url string) error
}

type service struct{}

func NewService() IService {
	return &service{}
}

func (s *service) Clone(dir string, url string) (err error) {
	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL: url,
		Auth: &http.BasicAuth{
			Username: "N/A",
			Password: os.Getenv("GITLAB_TOKEN"),
		},
		Depth: 1,
	})

	return
}

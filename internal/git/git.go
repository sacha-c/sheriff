package git

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

type IService interface {
	Clone(dir string, url string) error
}

type service struct {
	client iclient
	token  string
}

func New(token string) IService {
	return &service{
		client: &client{},
		token:  token,
	}
}

func (s *service) Clone(dir string, url string) (err error) {
	_, err = s.client.PlainClone(dir, false, &git.CloneOptions{
		URL: url,
		Auth: &http.BasicAuth{
			Username: "N/A",
			Password: s.token,
		},
		Depth: 1,
	})

	return
}

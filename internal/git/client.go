// This client is a thin wrapper around the go-git library. It provides an interface to the Git client
// The main purpose of this client is to provide an interface to the GitLab client which can be mocked in tests.
// As such this MUST be as thin as possible and MUST not contain any business logic, since it is not testable.
package git

import (
	"github.com/go-git/go-git/v5"
)

type iclient interface {
	PlainClone(path string, isBare bool, o *git.CloneOptions) (*git.Repository, error)
}

type client struct {
}

func (c *client) PlainClone(path string, isBare bool, o *git.CloneOptions) (*git.Repository, error) {
	return git.PlainClone(path, isBare, o)
}

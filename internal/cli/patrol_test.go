package cli

import (
	"flag"
	"fmt"
	"sheriff/internal/patrol"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestPatrolActionEmptyRun(t *testing.T) {
	context := cli.NewContext(cli.NewApp(), flag.NewFlagSet("flagset", flag.ContinueOnError), nil)

	err := PatrolAction(context)

	assert.Nil(t, err)
}

func TestParseUrls(t *testing.T) {
	testCases := []struct {
		paths               []string
		wantProjectLocation *patrol.ProjectLocation
		wantError           bool
	}{
		{[]string{"gitlab://namespace/project"}, &patrol.ProjectLocation{Type: "gitlab", Path: "namespace/project"}, false},
		{[]string{"gitlab://namespace/subgroup/project"}, &patrol.ProjectLocation{Type: "gitlab", Path: "namespace/subgroup/project"}, false},
		{[]string{"gitlab://namespace"}, &patrol.ProjectLocation{Type: "gitlab", Path: "namespace"}, false},
		{[]string{"github://organization"}, &patrol.ProjectLocation{Type: "github", Path: "organization"}, true},
		{[]string{"github://organization/project"}, &patrol.ProjectLocation{Type: "github", Path: "organization/project"}, true},
		{[]string{"unknown://namespace/project"}, nil, true},
		{[]string{"unknown://not a path"}, nil, true},
		{[]string{"not a url"}, nil, true},
	}

	for _, tc := range testCases {
		urls, err := parseUrls(tc.paths)

		fmt.Print(urls)

		if tc.wantError {
			assert.NotNil(t, err)
		} else {
			assert.Equal(t, tc.wantProjectLocation, &(urls[0]))
		}
	}
}

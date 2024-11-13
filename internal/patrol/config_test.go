package patrol

import (
	"sheriff/internal/scanner"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfiguration(t *testing.T) {
	testCases := []struct {
		filename   string
		wantFound  bool
		wantErr    bool
		wantConfig scanner.ProjectConfig
	}{
		{"testdata/valid.toml", true, false, scanner.ProjectConfig{SlackChannel: "the-devils-slack-channel"}},
		{"testdata/invalid.toml", true, true, scanner.ProjectConfig{}},
		{"testdata/nonexistent.toml", false, false, scanner.ProjectConfig{}},
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			got, found, err := getConfiguration(tc.filename)

			assert.Equal(t, tc.wantFound, found)
			assert.Equal(t, err != nil, tc.wantErr)
			assert.Equal(t, tc.wantConfig, got)
		})
	}
}

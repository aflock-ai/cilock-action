package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetect_GitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	// Make sure GitLab is not also set
	t.Setenv("GITLAB_CI", "")

	p := Detect()
	assert.Equal(t, PlatformGitHub, p)
	assert.Equal(t, "github", p.String())
}

func TestDetect_GitLab(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "true")

	p := Detect()
	assert.Equal(t, PlatformGitLab, p)
	assert.Equal(t, "gitlab", p.String())
}

func TestDetect_CLI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")

	p := Detect()
	assert.Equal(t, PlatformCLI, p)
	assert.Equal(t, "cli", p.String())
}

func TestDetect_GitHubTakesPrecedenceOverGitLab(t *testing.T) {
	// If both are set, GitHub wins because it's checked first.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITLAB_CI", "true")

	p := Detect()
	assert.Equal(t, PlatformGitHub, p)
}

func TestDetect_GitHubFalseIsNotGitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	t.Setenv("GITLAB_CI", "")

	p := Detect()
	// "false" != "true", so should not be GitHub
	assert.Equal(t, PlatformCLI, p)
}

func TestDetect_GitLabFalseIsNotGitLab(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "false")

	p := Detect()
	assert.Equal(t, PlatformCLI, p)
}

func TestPlatformString_Unknown(t *testing.T) {
	p := PlatformUnknown
	assert.Equal(t, "unknown", p.String())
}

func TestPlatformString_AllValues(t *testing.T) {
	tests := []struct {
		platform Platform
		expected string
	}{
		{PlatformUnknown, "unknown"},
		{PlatformGitHub, "github"},
		{PlatformGitLab, "gitlab"},
		{PlatformCLI, "cli"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.platform.String())
		})
	}
}

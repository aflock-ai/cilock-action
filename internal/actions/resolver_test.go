package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseActionRef_SimpleOwnerRepo(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("actions/checkout@v4")
	require.NoError(t, err)
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "checkout", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "v4", gitRef)
}

func TestParseActionRef_OwnerRepoWithSubpath(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("actions/aws/login@v2")
	require.NoError(t, err)
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "aws", repo)
	assert.Equal(t, "login", subpath)
	assert.Equal(t, "v2", gitRef)
}

func TestParseActionRef_DeepSubpath(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("my-org/my-repo/path/to/action@main")
	require.NoError(t, err)
	assert.Equal(t, "my-org", owner)
	assert.Equal(t, "my-repo", repo)
	assert.Equal(t, "path/to/action", subpath)
	assert.Equal(t, "main", gitRef)
}

func TestParseActionRef_SHA(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29")
	require.NoError(t, err)
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "checkout", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "a5ac7e51b41094c92402da3b24376905380afc29", gitRef)
}

func TestParseActionRef_BranchRef(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("my-org/my-action@feature/my-branch")
	require.NoError(t, err)
	assert.Equal(t, "my-org", owner)
	assert.Equal(t, "my-action", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "feature/my-branch", gitRef)
}

func TestParseActionRef_MissingAtSign(t *testing.T) {
	_, _, _, _, err := parseActionRef("actions/checkout")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing @ref")
}

func TestParseActionRef_OnlyOwner(t *testing.T) {
	_, _, _, _, err := parseActionRef("actions@v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected owner/repo")
}

func TestParseActionRef_EmptyString(t *testing.T) {
	_, _, _, _, err := parseActionRef("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing @ref")
}

func TestParseActionRef_OnlyAtSign(t *testing.T) {
	_, _, _, _, err := parseActionRef("@v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected owner/repo")
}

func TestParseActionRef_MultipleAtSigns(t *testing.T) {
	// LastIndex of "@" should handle this: it grabs the last @
	owner, repo, subpath, gitRef, err := parseActionRef("owner/repo@feature@v2")
	require.NoError(t, err)
	assert.Equal(t, "owner", owner)
	assert.Equal(t, "repo@feature", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "v2", gitRef)
}

func TestParseActionRef_VersionWithV(t *testing.T) {
	owner, repo, _, gitRef, err := parseActionRef("hashicorp/setup-terraform@v3.1.0")
	require.NoError(t, err)
	assert.Equal(t, "hashicorp", owner)
	assert.Equal(t, "setup-terraform", repo)
	assert.Equal(t, "v3.1.0", gitRef)
}

func TestParseActionRef_SubpathWithDots(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("org/repo/sub.path/action@v1")
	require.NoError(t, err)
	assert.Equal(t, "org", owner)
	assert.Equal(t, "repo", repo)
	assert.Equal(t, "sub.path/action", subpath)
	assert.Equal(t, "v1", gitRef)
}

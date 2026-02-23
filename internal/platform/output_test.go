package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetOutput_GitHubWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")

	// Create the file so GITHUB_OUTPUT points to something real
	err := os.WriteFile(outputFile, nil, 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_OUTPUT", outputFile)

	err = SetOutput(PlatformGitHub, "result", "success")
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "result=success\n", string(data))
}

func TestSetOutput_GitHubMultilineValue(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")
	err := os.WriteFile(outputFile, nil, 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_OUTPUT", outputFile)

	err = SetOutput(PlatformGitHub, "json", "line1\nline2\nline3")
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "json<<EOF\nline1\nline2\nline3\nEOF\n", string(data))
}

func TestSetOutput_GitHubWithoutFileUsesLegacyFormat(t *testing.T) {
	// When GITHUB_OUTPUT is not set, it falls back to the deprecated
	// ::set-output format. We can't easily capture stdout here without
	// redirecting, but we confirm it doesn't error.
	t.Setenv("GITHUB_OUTPUT", "")

	err := SetOutput(PlatformGitHub, "key", "val")
	require.NoError(t, err)
}

func TestSetOutput_GitHubAppendsToExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")

	// Pre-populate with existing content
	err := os.WriteFile(outputFile, []byte("existing=content\n"), 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_OUTPUT", outputFile)

	err = SetOutput(PlatformGitHub, "new-key", "new-value")
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "existing=content\nnew-key=new-value\n", string(data))
}

func TestSetOutput_GitLabWithDotenvFile(t *testing.T) {
	tmpDir := t.TempDir()
	dotenvFile := filepath.Join(tmpDir, "cilock.env")

	t.Setenv("CILOCK_DOTENV_FILE", dotenvFile)

	err := SetOutput(PlatformGitLab, "result", "pass")
	require.NoError(t, err)

	data, err := os.ReadFile(dotenvFile)
	require.NoError(t, err)
	assert.Equal(t, "result=pass\n", string(data))
}

func TestSetOutput_GitLabDefaultDotenvFile(t *testing.T) {
	// When CILOCK_DOTENV_FILE is not set, it writes to "cilock.env" in CWD.
	// Use a temp dir as the working directory to avoid polluting the project.
	tmpDir := t.TempDir()

	t.Setenv("CILOCK_DOTENV_FILE", "")

	// We need to change to tmpDir so the default "cilock.env" goes there
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	err = SetOutput(PlatformGitLab, "key", "val")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "cilock.env"))
	require.NoError(t, err)
	assert.Equal(t, "key=val\n", string(data))
}

func TestSetOutput_CLIPrintsToStdout(t *testing.T) {
	// CLI platform just prints — no file to verify, but it should not error.
	err := SetOutput(PlatformCLI, "key", "val")
	require.NoError(t, err)
}

func TestSetOutput_UnknownPlatform(t *testing.T) {
	err := SetOutput(PlatformUnknown, "key", "val")
	require.NoError(t, err)
}

func TestWriteSummary_GitHub(t *testing.T) {
	tmpDir := t.TempDir()
	summaryFile := filepath.Join(tmpDir, "step_summary.md")
	err := os.WriteFile(summaryFile, nil, 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)

	err = WriteSummary(PlatformGitHub, "## Test Results\nAll passed!")
	require.NoError(t, err)

	data, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.Equal(t, "## Test Results\nAll passed!\n", string(data))
}

func TestWriteSummary_GitHubAppendsToExisting(t *testing.T) {
	tmpDir := t.TempDir()
	summaryFile := filepath.Join(tmpDir, "step_summary.md")
	err := os.WriteFile(summaryFile, []byte("# Existing Summary\n"), 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)

	err = WriteSummary(PlatformGitHub, "More content")
	require.NoError(t, err)

	data, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	assert.Equal(t, "# Existing Summary\nMore content\n", string(data))
}

func TestWriteSummary_GitHubNoSummaryFile(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")

	// Should be a no-op, not an error
	err := WriteSummary(PlatformGitHub, "content")
	require.NoError(t, err)
}

func TestWriteSummary_NonGitHubIsNoOp(t *testing.T) {
	// WriteSummary only works for GitHub
	err := WriteSummary(PlatformGitLab, "content")
	require.NoError(t, err)

	err = WriteSummary(PlatformCLI, "content")
	require.NoError(t, err)
}

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout to a pipe, runs fn, then returns
// whatever was written. The original stdout is restored on cleanup.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	origStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	fn()

	require.NoError(t, w.Close())
	buf, err := os.ReadFile(r.Name())
	// os.ReadFile on a pipe fd won't work; use io-style read instead.
	// Actually, let's just read from the reader end.
	_ = buf
	_ = err

	// Read all from the pipe reader.
	data := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, readErr := r.Read(tmp)
		if n > 0 {
			data = append(data, tmp[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	return string(data)
}

// ---------------------------------------------------------------------------
// SetOutput
// ---------------------------------------------------------------------------

func TestSetOutput_GitHubWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")

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

func TestSetOutput_GitHubWithoutFile_FallsBackToSetOutputCommand(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", "")

	got := captureStdout(t, func() {
		err := SetOutput(PlatformGitHub, "mykey", "myval")
		require.NoError(t, err)
	})

	assert.Equal(t, "::set-output name=mykey::myval\n", got)
}

func TestSetOutput_GitHubAppendsToExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")

	err := os.WriteFile(outputFile, []byte("existing=content\n"), 0o644)
	require.NoError(t, err)

	t.Setenv("GITHUB_OUTPUT", outputFile)

	err = SetOutput(PlatformGitHub, "new-key", "new-value")
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "existing=content\nnew-key=new-value\n", string(data))
}

func TestSetOutput_GitLabWithCustomDotenvFile(t *testing.T) {
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
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	t.Setenv("CILOCK_DOTENV_FILE", "")

	err := SetOutput(PlatformGitLab, "key", "val")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "cilock.env"))
	require.NoError(t, err)
	assert.Equal(t, "key=val\n", string(data))
}

func TestSetOutput_GitLabAppendsToExistingDotenv(t *testing.T) {
	tmpDir := t.TempDir()
	dotenvFile := filepath.Join(tmpDir, "cilock.env")

	err := os.WriteFile(dotenvFile, []byte("first=one\n"), 0o644)
	require.NoError(t, err)

	t.Setenv("CILOCK_DOTENV_FILE", dotenvFile)

	err = SetOutput(PlatformGitLab, "second", "two")
	require.NoError(t, err)

	data, err := os.ReadFile(dotenvFile)
	require.NoError(t, err)
	assert.Equal(t, "first=one\nsecond=two\n", string(data))
}

func TestSetOutput_CLIPrintsKeyValueToStdout(t *testing.T) {
	got := captureStdout(t, func() {
		err := SetOutput(PlatformCLI, "status", "ok")
		require.NoError(t, err)
	})

	assert.Equal(t, "status=ok\n", got)
}

func TestSetOutput_UnknownPlatformPrintsToStdout(t *testing.T) {
	got := captureStdout(t, func() {
		err := SetOutput(PlatformUnknown, "debug", "true")
		require.NoError(t, err)
	})

	assert.Equal(t, "debug=true\n", got)
}

// ---------------------------------------------------------------------------
// WriteSummary
// ---------------------------------------------------------------------------

func TestWriteSummary_GitHubWithSummaryFile(t *testing.T) {
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

func TestWriteSummary_GitHubNoSummaryFileIsNoOp(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")

	err := WriteSummary(PlatformGitHub, "content")
	require.NoError(t, err)
}

func TestWriteSummary_GitLabIsNoOp(t *testing.T) {
	err := WriteSummary(PlatformGitLab, "content")
	require.NoError(t, err)
}

func TestWriteSummary_CLIIsNoOp(t *testing.T) {
	err := WriteSummary(PlatformCLI, "content")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// setGitHubOutput (exercised through SetOutput for coverage)
// ---------------------------------------------------------------------------

func TestSetGitHubOutput_SingleLineFormat(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")
	require.NoError(t, os.WriteFile(outputFile, nil, 0o644))

	t.Setenv("GITHUB_OUTPUT", outputFile)

	err := SetOutput(PlatformGitHub, "simple", "value-no-newlines")
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "simple=value-no-newlines\n", string(data))
	assert.NotContains(t, string(data), "EOF", "single-line values must not use heredoc")
}

func TestSetGitHubOutput_MultilineUsesHeredoc(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")
	require.NoError(t, os.WriteFile(outputFile, nil, 0o644))

	t.Setenv("GITHUB_OUTPUT", outputFile)

	multiline := "{\n  \"key\": \"value\"\n}"
	err := SetOutput(PlatformGitHub, "payload", multiline)
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	expected := "payload<<EOF\n{\n  \"key\": \"value\"\n}\nEOF\n"
	assert.Equal(t, expected, string(data))
}

func TestSetGitHubOutput_EmptyValueIsSingleLine(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "github_output")
	require.NoError(t, os.WriteFile(outputFile, nil, 0o644))

	t.Setenv("GITHUB_OUTPUT", outputFile)

	err := SetOutput(PlatformGitHub, "empty", "")
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Equal(t, "empty=\n", string(data))
}

// ---------------------------------------------------------------------------
// setGitLabOutput (exercised through SetOutput for coverage)
// ---------------------------------------------------------------------------

func TestSetGitLabOutput_DefaultDotenvFileName(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	t.Setenv("CILOCK_DOTENV_FILE", "")

	err := SetOutput(PlatformGitLab, "artifact", "signed")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "cilock.env"))
	require.NoError(t, err)
	assert.Equal(t, "artifact=signed\n", string(data))
}

func TestSetGitLabOutput_CustomDotenvFileViaEnv(t *testing.T) {
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom-output.env")
	t.Setenv("CILOCK_DOTENV_FILE", customPath)

	err := SetOutput(PlatformGitLab, "custom-key", "custom-val")
	require.NoError(t, err)

	data, err := os.ReadFile(customPath)
	require.NoError(t, err)
	assert.Equal(t, "custom-key=custom-val\n", string(data))
}

func TestSetGitLabOutput_CreatesFileIfNotExists(t *testing.T) {
	tmpDir := t.TempDir()
	dotenvFile := filepath.Join(tmpDir, "brand-new.env")
	t.Setenv("CILOCK_DOTENV_FILE", dotenvFile)

	// File does not exist yet -- setGitLabOutput should create it.
	_, err := os.Stat(dotenvFile)
	require.True(t, os.IsNotExist(err), "file should not exist before test")

	err = SetOutput(PlatformGitLab, "created", "yes")
	require.NoError(t, err)

	data, err := os.ReadFile(dotenvFile)
	require.NoError(t, err)
	assert.Equal(t, "created=yes\n", string(data))
}

func TestSetGitLabOutput_MultipleWritesAppend(t *testing.T) {
	tmpDir := t.TempDir()
	dotenvFile := filepath.Join(tmpDir, "multi.env")
	t.Setenv("CILOCK_DOTENV_FILE", dotenvFile)

	require.NoError(t, SetOutput(PlatformGitLab, "a", "1"))
	require.NoError(t, SetOutput(PlatformGitLab, "b", "2"))
	require.NoError(t, SetOutput(PlatformGitLab, "c", "3"))

	data, err := os.ReadFile(dotenvFile)
	require.NoError(t, err)
	assert.Equal(t, "a=1\nb=2\nc=3\n", string(data))
}

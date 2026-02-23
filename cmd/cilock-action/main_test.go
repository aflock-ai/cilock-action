// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cilockattest "github.com/aflock-ai/cilock-action/internal/attestation"
	"github.com/aflock-ai/cilock-action/internal/bypass"
	"github.com/aflock-ai/cilock-action/internal/config"
	"github.com/aflock-ai/cilock-action/internal/platform"
	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSummary_NormalGitOID(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs:          []string{"abcdef1234567890abcdef1234567890abcdef12"},
		AttestationFiles: []string{"/tmp/attestation.json"},
	}

	summary := buildSummary(result)
	assert.Contains(t, summary, "abcdef123456...")
	assert.Contains(t, summary, "attestation.json")
}

func TestBuildSummary_ShortGitOID_NoPanic(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs: []string{"abc"},
	}

	// This should NOT panic even though oid is < 12 chars
	summary := buildSummary(result)
	assert.Contains(t, summary, "abc")
	assert.NotContains(t, summary, "...")
}

func TestBuildSummary_EmptyGitOID_NoPanic(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs: []string{""},
	}

	// Empty string should not panic
	summary := buildSummary(result)
	assert.Contains(t, summary, "GitOID")
}

func TestBuildSummary_ExactlyTwelveChars(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs: []string{"123456789012"},
	}

	summary := buildSummary(result)
	// Exactly 12 chars — should NOT add "..." since there's nothing truncated
	assert.Contains(t, summary, "123456789012")
}

func TestBuildSummary_NoGitOIDs(t *testing.T) {
	result := &cilockattest.Result{
		AttestationFiles: []string{"/tmp/att.json"},
	}

	summary := buildSummary(result)
	assert.NotContains(t, summary, "GitOID")
	assert.Contains(t, summary, "att.json")
}

func TestBuildSummary_NoResults(t *testing.T) {
	result := &cilockattest.Result{}

	summary := buildSummary(result)
	assert.Contains(t, summary, "cilock-action Attestation")
}

func TestBuildSummary_MultipleFiles(t *testing.T) {
	result := &cilockattest.Result{
		AttestationFiles: []string{
			"/tmp/a.json",
			"/tmp/b-export.json",
		},
	}

	summary := buildSummary(result)
	assert.Contains(t, summary, "a.json")
	assert.Contains(t, summary, "b-export.json")
}

// ---------------------------------------------------------------------------
// writeOutputs tests
// ---------------------------------------------------------------------------

// setupGitHubOutputFiles creates temp files for GITHUB_OUTPUT and
// GITHUB_STEP_SUMMARY so the GitHub platform output helpers work.
// It sets the env vars via t.Setenv (auto-cleaned up) and returns the
// paths so callers can inspect file contents after the test.
func setupGitHubOutputFiles(t *testing.T) (outputPath, summaryPath string) {
	t.Helper()
	dir := t.TempDir()
	outputPath = filepath.Join(dir, "github_output")
	summaryPath = filepath.Join(dir, "github_step_summary")
	// Create the files so OpenFile with O_APPEND works.
	require.NoError(t, os.WriteFile(outputPath, nil, 0o644))
	require.NoError(t, os.WriteFile(summaryPath, nil, 0o644))
	t.Setenv("GITHUB_OUTPUT", outputPath)
	t.Setenv("GITHUB_STEP_SUMMARY", summaryPath)
	return outputPath, summaryPath
}

func TestWriteOutputs_NilResult(t *testing.T) {
	err := writeOutputs(platform.PlatformGitHub, nil)
	require.NoError(t, err)
}

func TestWriteOutputs_GitOIDs(t *testing.T) {
	outputPath, _ := setupGitHubOutputFiles(t)

	result := &cilockattest.Result{
		GitOIDs: []string{"abc123def456"},
	}

	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "git_oid=abc123def456")
}

func TestWriteOutputs_AttestationFiles(t *testing.T) {
	outputPath, _ := setupGitHubOutputFiles(t)

	result := &cilockattest.Result{
		AttestationFiles: []string{"/tmp/attestation.json"},
	}

	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "attestation_file=/tmp/attestation.json")
}

func TestWriteOutputs_BothGitOIDAndAttestationFile(t *testing.T) {
	outputPath, summaryPath := setupGitHubOutputFiles(t)

	result := &cilockattest.Result{
		GitOIDs:          []string{"deadbeef1234"},
		AttestationFiles: []string{"/out/att.json"},
	}

	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "git_oid=deadbeef1234")
	assert.Contains(t, content, "attestation_file=/out/att.json")

	// Summary file should also have been written.
	summaryData, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	assert.Contains(t, string(summaryData), "cilock-action Attestation")
}

// ---------------------------------------------------------------------------
// parseConfig tests
// ---------------------------------------------------------------------------

func TestParseConfig_GitHub(t *testing.T) {
	// ParseGitHub reads INPUT_* env vars.
	t.Setenv("INPUT_COMMAND", "echo hello")
	t.Setenv("INPUT_STEP", "build")

	cfg, err := parseConfig(platform.PlatformGitHub)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "echo hello", cfg.Command)
	assert.Equal(t, "build", cfg.Step)
}

func TestParseConfig_GitLab(t *testing.T) {
	// ParseGitLab reads CILOCK_* env vars.
	t.Setenv("CILOCK_COMMAND", "make test")
	t.Setenv("CILOCK_STEP", "test")

	cfg, err := parseConfig(platform.PlatformGitLab)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "make test", cfg.Command)
	assert.Equal(t, "test", cfg.Step)
}

func TestParseConfig_CLI_ReturnsError(t *testing.T) {
	cfg, err := parseConfig(platform.PlatformCLI)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CLI mode not yet implemented")
}

func TestParseConfig_Unknown_ReturnsError(t *testing.T) {
	cfg, err := parseConfig(platform.PlatformUnknown)
	assert.Nil(t, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CLI mode not yet implemented")
}

// ---------------------------------------------------------------------------
// isRefPinned tests
// ---------------------------------------------------------------------------

func TestIsRefPinned_FullSHA(t *testing.T) {
	assert.True(t, isRefPinned("actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332"))
}

func TestIsRefPinned_Tag(t *testing.T) {
	assert.False(t, isRefPinned("actions/checkout@v4"))
}

func TestIsRefPinned_Branch(t *testing.T) {
	assert.False(t, isRefPinned("actions/checkout@main"))
}

func TestIsRefPinned_ShortSHA(t *testing.T) {
	assert.False(t, isRefPinned("actions/checkout@692973e"))
}

func TestIsRefPinned_NoAt(t *testing.T) {
	assert.False(t, isRefPinned("actions/checkout"))
}

func TestIsRefPinned_InvalidHex(t *testing.T) {
	// 40 chars but not valid hex
	assert.False(t, isRefPinned("actions/checkout@zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
}

func TestIsRefPinned_DockerRef(t *testing.T) {
	assert.False(t, isRefPinned("docker://alpine:3.19"))
}

// ---------------------------------------------------------------------------
// run / runCommand / writeOutputs integration tests
// ---------------------------------------------------------------------------

// setupGitHubEnvForRun configures the minimal GitHub Actions env vars
// needed to call run() without hitting external services.
// It disables sigstore and archivista, and clears potentially conflicting
// platform env vars.
func setupGitHubEnvForRun(t *testing.T) {
	t.Helper()
	// Platform detection
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITLAB_CI", "")
	// Disable external services
	t.Setenv("INPUT_ENABLE_SIGSTORE", "false")
	t.Setenv("INPUT_ENABLE_ARCHIVISTA", "false")
	// Override default attestations to exclude "github" which requires OIDC token
	t.Setenv("INPUT_ATTESTATIONS", "environment git")
}

// setupGitLabEnvForRun configures the minimal GitLab CI env vars
// needed to call run() without hitting external services.
func setupGitLabEnvForRun(t *testing.T) {
	t.Helper()
	// Platform detection
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("GITHUB_ACTIONS", "")
	// Disable external services
	t.Setenv("CILOCK_ENABLE_SIGSTORE", "false")
	t.Setenv("CILOCK_ENABLE_ARCHIVISTA", "false")
	// Override default attestations to exclude "gitlab" which may require CI env
	t.Setenv("CILOCK_ATTESTATIONS", "environment git")
}

func TestRun_GitHubPlatform_CommandMode(t *testing.T) {
	attestation.RegisterLegacyAliases()

	setupGitHubEnvForRun(t)
	t.Setenv("INPUT_COMMAND", "echo hello")
	t.Setenv("INPUT_STEP", "test-build")

	outfile := filepath.Join(t.TempDir(), "attestation.json")
	t.Setenv("INPUT_OUTFILE", outfile)

	// Set up GITHUB_OUTPUT and GITHUB_STEP_SUMMARY so writeOutputs works
	setupGitHubOutputFiles(t)

	err := run(context.Background())
	require.NoError(t, err)

	// The collection result has empty AttestorName, so the base outfile is used.
	data, err := os.ReadFile(outfile)
	require.NoError(t, err, "outfile should exist")
	assert.NotEmpty(t, data)

	// Verify it's valid JSON (DSSE envelope structure)
	var envelope map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &envelope), "outfile should contain valid JSON")
	assert.Contains(t, envelope, "payloadType", "envelope should have payloadType field")
	assert.Contains(t, envelope, "payload", "envelope should have payload field")
}

func TestRun_GitHubPlatform_BypassMode(t *testing.T) {
	attestation.RegisterLegacyAliases()
	bypass.PenaltyDelay = 0

	setupGitHubEnvForRun(t)
	t.Setenv("INPUT_COMMAND", "echo bypass-test")
	t.Setenv("INPUT_STEP", "test")
	t.Setenv("CILOCK_BYPASS", "true")

	err := run(context.Background())
	require.NoError(t, err)
}

func TestRun_GitHubPlatform_ValidationFailure(t *testing.T) {
	attestation.RegisterLegacyAliases()

	setupGitHubEnvForRun(t)
	// Don't set INPUT_COMMAND or INPUT_ACTION — validation should fail
	t.Setenv("INPUT_COMMAND", "")
	t.Setenv("INPUT_ACTION_REF", "")
	t.Setenv("INPUT_STEP", "test")

	err := run(context.Background())
	require.Error(t, err, "validation should fail without command or action ref")
}

func TestRunCommand_Success(t *testing.T) {
	attestation.RegisterLegacyAliases()

	outfile := filepath.Join(t.TempDir(), "cmd-attestation.json")
	cfg := &config.Config{
		Command: "echo hello",
		Step:    "cmd-test",
		OutFile: outfile,
	}

	err := runCommand(context.Background(), cfg, platform.PlatformGitHub)
	require.NoError(t, err)
}

func TestRunCommand_FailingCommand(t *testing.T) {
	attestation.RegisterLegacyAliases()

	outfile := filepath.Join(t.TempDir(), "fail-attestation.json")
	cfg := &config.Config{
		Command: "false",
		Step:    "fail",
		OutFile: outfile,
	}

	err := runCommand(context.Background(), cfg, platform.PlatformGitHub)
	require.Error(t, err, "a failing command should propagate an error")
}

func TestWriteOutputs_Summary(t *testing.T) {
	outputPath, summaryPath := setupGitHubOutputFiles(t)

	result := &cilockattest.Result{
		GitOIDs:          []string{"aabbccdd11223344"},
		AttestationFiles: []string{"/tmp/test-attestation.json"},
	}

	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)

	// Verify GITHUB_OUTPUT was written
	outputData, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	outputContent := string(outputData)
	assert.Contains(t, outputContent, "git_oid=aabbccdd11223344")
	assert.Contains(t, outputContent, "attestation_file=/tmp/test-attestation.json")

	// Verify GITHUB_STEP_SUMMARY was written
	summaryData, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	summaryContent := string(summaryData)
	assert.Contains(t, summaryContent, "cilock-action Attestation")
	assert.Contains(t, summaryContent, "aabbccdd1122...")
	assert.Contains(t, summaryContent, "test-attestation.json")
}

func TestRun_GitLabPlatform_CommandMode(t *testing.T) {
	attestation.RegisterLegacyAliases()

	setupGitLabEnvForRun(t)
	t.Setenv("CILOCK_COMMAND", "echo gitlab-test")
	t.Setenv("CILOCK_STEP", "gl-step")

	outfile := filepath.Join(t.TempDir(), "gitlab-attestation.json")
	t.Setenv("CILOCK_OUTFILE", outfile)

	err := run(context.Background())
	require.NoError(t, err)

	// Verify the outfile was written
	data, err := os.ReadFile(outfile)
	require.NoError(t, err, "outfile should exist")
	assert.NotEmpty(t, data)

	// Verify it's valid JSON
	var envelope map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &envelope), "outfile should contain valid JSON")
	assert.Contains(t, envelope, "payloadType")
}

// ---------------------------------------------------------------------------
// runAction integration tests — uses CILOCK_LOCAL_ACTION_DIR with a local
// composite action to avoid network calls.
// ---------------------------------------------------------------------------

// createLocalCompositeAction creates a local composite action fixture that
// echoes a string. Returns the base local action dir to set as
// CILOCK_LOCAL_ACTION_DIR.
func createLocalCompositeAction(t *testing.T, owner, repo, ref string) string {
	t.Helper()
	baseDir := t.TempDir()
	actionDir := filepath.Join(baseDir, owner, repo, ref)
	require.NoError(t, os.MkdirAll(actionDir, 0o755))

	actionYAML := `name: Test Composite Action
description: A test composite action for integration testing
inputs:
  greeting:
    description: What to say
    default: hello
runs:
  using: composite
  steps:
    - run: echo "hello from composite"
      shell: bash
`
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYAML), 0o644))
	return baseDir
}

func TestRun_GitHubPlatform_ActionMode(t *testing.T) {
	attestation.RegisterLegacyAliases()

	setupGitHubEnvForRun(t)

	// Create a local composite action fixture
	localDir := createLocalCompositeAction(t, "test-org", "test-action", "v1")
	t.Setenv("CILOCK_LOCAL_ACTION_DIR", localDir)

	t.Setenv("INPUT_ACTION_REF", "test-org/test-action@v1")
	t.Setenv("INPUT_COMMAND", "")
	t.Setenv("INPUT_STEP", "action-test")

	outfile := filepath.Join(t.TempDir(), "action-attestation.json")
	t.Setenv("INPUT_OUTFILE", outfile)

	setupGitHubOutputFiles(t)

	err := run(context.Background())
	require.NoError(t, err)

	// Verify attestation file was created (may have attestor suffix)
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(outfile), "*.json"))
	require.NoError(t, err)
	assert.NotEmpty(t, matches, "at least one attestation JSON file should exist")
}

func TestRunAction_WithLocalCompositeAction(t *testing.T) {
	attestation.RegisterLegacyAliases()

	// Create local action fixture
	localDir := createLocalCompositeAction(t, "myorg", "myaction", "v2")
	t.Setenv("CILOCK_LOCAL_ACTION_DIR", localDir)

	outfile := filepath.Join(t.TempDir(), "action-att.json")
	cfg := &config.Config{
		ActionRef:    "myorg/myaction@v2",
		Step:         "action-step",
		OutFile:      outfile,
		ActionInputs: map[string]string{"greeting": "world"},
		ActionEnv:    map[string]string{},
	}

	setupGitHubOutputFiles(t)

	err := runAction(context.Background(), cfg, platform.PlatformGitHub)
	require.NoError(t, err)
}

func TestRun_GitHubPlatform_ActionMode_UnpinnedRef(t *testing.T) {
	attestation.RegisterLegacyAliases()

	setupGitHubEnvForRun(t)

	localDir := createLocalCompositeAction(t, "test-org", "test-action", "main")
	t.Setenv("CILOCK_LOCAL_ACTION_DIR", localDir)

	// Use a tag ref (not pinned to SHA) — should emit warning but succeed
	t.Setenv("INPUT_ACTION_REF", "test-org/test-action@main")
	t.Setenv("INPUT_COMMAND", "")
	t.Setenv("INPUT_STEP", "unpinned-test")

	outfile := filepath.Join(t.TempDir(), "attestation.json")
	t.Setenv("INPUT_OUTFILE", outfile)

	setupGitHubOutputFiles(t)

	err := run(context.Background())
	require.NoError(t, err)
}

func TestWriteOutputs_NoGitOIDs(t *testing.T) {
	_, summaryPath := setupGitHubOutputFiles(t)

	result := &cilockattest.Result{
		AttestationFiles: []string{"/tmp/att.json"},
	}

	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)

	// Summary should still be written
	data, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "cilock-action Attestation")
}

func TestWriteOutputs_NoAttestationFiles(t *testing.T) {
	outputPath, summaryPath := setupGitHubOutputFiles(t)

	result := &cilockattest.Result{
		GitOIDs: []string{"abc123"},
	}

	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "git_oid=abc123")

	// Summary should have the GitOID
	sdata, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	assert.Contains(t, string(sdata), "abc123")
}

func TestWriteOutputs_EmptyResult(t *testing.T) {
	setupGitHubOutputFiles(t)

	result := &cilockattest.Result{}
	err := writeOutputs(platform.PlatformGitHub, result)
	require.NoError(t, err)
}

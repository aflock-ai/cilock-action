package actions

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateSimpleCondition_Always(t *testing.T) {
	result, warning := evaluateSimpleCondition("always()")
	assert.True(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_Success(t *testing.T) {
	result, warning := evaluateSimpleCondition("success()")
	assert.True(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_Failure(t *testing.T) {
	result, warning := evaluateSimpleCondition("failure()")
	assert.False(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_True(t *testing.T) {
	result, warning := evaluateSimpleCondition("true")
	assert.True(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_False(t *testing.T) {
	result, warning := evaluateSimpleCondition("false")
	assert.False(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_CaseInsensitive(t *testing.T) {
	result, warning := evaluateSimpleCondition("TRUE")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("True")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("FALSE")
	assert.False(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("False")
	assert.False(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("Always()")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("ALWAYS()")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("Success()")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("Failure()")
	assert.False(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_EnvVar(t *testing.T) {
	t.Setenv("CILOCK_TEST_COND_VAR", "notempty")
	result, warning := evaluateSimpleCondition("env.CILOCK_TEST_COND_VAR")
	assert.True(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_EnvVarMissing(t *testing.T) {
	// Ensure the variable doesn't exist
	os.Unsetenv("CILOCK_TEST_COND_MISSING") //nolint:errcheck
	result, warning := evaluateSimpleCondition("env.CILOCK_TEST_COND_MISSING")
	assert.False(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_Default(t *testing.T) {
	// Unknown expressions default to false (fail-safe) and return a warning
	result, warning := evaluateSimpleCondition("some_unknown_expression")
	assert.False(t, result)
	assert.Contains(t, warning, "unrecognized condition")

	result, warning = evaluateSimpleCondition("${{ github.event_name == 'push' }}")
	assert.False(t, result)
	assert.Contains(t, warning, "unrecognized condition")
}

func TestEvaluateSimpleCondition_Whitespace(t *testing.T) {
	result, warning := evaluateSimpleCondition("  always()  ")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("  false  ")
	assert.False(t, result)
	assert.Empty(t, warning)
}

func TestRunComposite_BasicSteps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "step1", Run: "echo hello", Shell: "bash"},
				{Name: "step2", Run: "echo world", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "hello")
	assert.Contains(t, output, "world")
}

func TestRunComposite_StepSkippedByCondition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "runs", Run: "echo visible", Shell: "bash"},
				{Name: "skipped", If: "false", Run: "echo invisible", Shell: "bash"},
				{Name: "also-runs", Run: "echo also-visible", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "visible")
	assert.NotContains(t, output, "invisible")
	assert.Contains(t, output, "also-visible")
}

func TestRunComposite_StepFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "fail-step", Run: "exit 1", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fail-step")
}

func TestRunComposite_ShellSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh/bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "sh-step", Run: "echo from-sh", Shell: "sh"},
				{Name: "bash-step", Run: "echo from-bash", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "from-sh")
	assert.Contains(t, output, "from-bash")
}

func TestRunComposite_StepEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{"ACTION_VAR": "action-level"},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{
					Name:  "env-step",
					Run:   "echo $STEP_VAR $ACTION_VAR",
					Shell: "bash",
					Env:   map[string]string{"STEP_VAR": "step-level"},
				},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "step-level")
	assert.Contains(t, output, "action-level")
}

func TestRunCompositeRun_WorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	tmpDir := t.TempDir()

	// Create a subdir to use as working directory
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	step := CompositeStep{
		Run:              "pwd",
		Shell:            "bash",
		WorkingDirectory: subDir,
	}

	env := BuildActionEnv(&ActionMetadata{}, tmpDir, nil, nil)
	err := r.runCompositeRun(context.Background(), step, env)
	require.NoError(t, err)

	output := strings.TrimSpace(stdout.String())
	// On macOS, /var is a symlink to /private/var, so pwd may report the resolved path
	assert.Contains(t, output, filepath.Base(subDir))
}

func TestRunComposite_DefaultShellIsBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				// No shell specified — should default to bash
				{Name: "default-shell", Run: "echo default-works"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "default-works")
}

func TestRunComposite_StepNameFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				// Unnamed step that fails — error should contain "step-1"
				{Run: "exit 1", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step-1")
}

func TestRunComposite_ContextCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "long-sleep", Run: "sleep 60", Shell: "bash"},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := r.runComposite(ctx, meta, t.TempDir())
	require.Error(t, err)
}

func TestRunCompositeRun_PythonShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python availability varies on windows")
	}

	// The composite runner invokes "python" (not "python3") for shell: "python"
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("python not available in PATH")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "python-step", Run: "print('hello-python')", Shell: "python"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "hello-python")
}

func TestRunComposite_EmptySteps(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)
}

func TestRunComposite_MultipleFailingSteps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "first-fail", Run: "exit 1", Shell: "bash"},
				{Name: "second-step", Run: "echo should-not-run", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "first-fail")
	assert.NotContains(t, stdout.String(), "should-not-run")
}

func TestEvaluateSimpleCondition_EnvVarWithQuotes(t *testing.T) {
	t.Setenv("CILOCK_QUOTED_VAR", "some-value")

	// The trimming logic in evaluateSimpleCondition strips trailing quotes, braces, etc.
	// Test that env.VAR_NAME with trailing }} or quotes is handled correctly.
	result, warning := evaluateSimpleCondition("env.CILOCK_QUOTED_VAR")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("env.CILOCK_QUOTED_VAR }}")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("env.CILOCK_QUOTED_VAR\"")
	assert.True(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("env.CILOCK_QUOTED_VAR'")
	assert.True(t, result)
	assert.Empty(t, warning)

	// Unset variable with trailing noise should still be false
	os.Unsetenv("CILOCK_NONEXISTENT_VAR") //nolint:errcheck
	result, warning = evaluateSimpleCondition("env.CILOCK_NONEXISTENT_VAR }}")
	assert.False(t, result)
	assert.Empty(t, warning)

	result, warning = evaluateSimpleCondition("env.CILOCK_NONEXISTENT_VAR\"")
	assert.False(t, result)
	assert.Empty(t, warning)
}

func TestEvaluateSimpleCondition_UnrecognizedReturnsWarning(t *testing.T) {
	result, warning := evaluateSimpleCondition("${{ github.actor == 'admin' }}")
	assert.False(t, result, "unrecognized expressions should be false")
	assert.Contains(t, warning, "unrecognized condition")
}

func TestRunCompositeUses_DepthExceeded(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
		depth:      maxCompositeDepth,
	}

	step := CompositeStep{
		Uses: "actions/checkout@v4",
	}

	err := r.runCompositeUses(context.Background(), step)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth exceeded")
}

func TestRunComposite_WithIfCondition_False(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "should-run", Run: "echo visible", Shell: "bash"},
				{Name: "should-skip", If: "false", Run: "echo invisible", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "visible")
	assert.NotContains(t, output, "invisible")
}

func TestRunComposite_WithIfCondition_Always(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "always-step", If: "always()", Run: "echo always-ran", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "always-ran")
}

func TestRunComposite_UnrecognizedCondition_Warning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout bytes.Buffer
	var stderr strings.Builder
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "weird-cond", If: "some-expression", Run: "echo should-not-run", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	// Step should be skipped (its output should not appear)
	assert.NotContains(t, stdout.String(), "should-not-run")
	// Warning about unrecognized condition should be emitted to stderr
	assert.Contains(t, stderr.String(), "unrecognized condition")
}

func TestRunComposite_NamedStep(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "My Step", Run: "echo named-step-output", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.NoError(t, err)

	// The step name should appear in the group marker on stderr
	assert.Contains(t, stderr.String(), "My Step")
	// The step should have actually run
	assert.Contains(t, stdout.String(), "named-step-output")
}

func TestRunComposite_StepWithUses_DepthExceeded(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
		depth:      maxCompositeDepth,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "nested-uses", Uses: "actions/checkout@v4"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth exceeded")
}

func TestRunCompositeRun_ShShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh not available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	step := CompositeStep{
		Run:   "echo from-sh-direct",
		Shell: "sh",
	}
	env := BuildActionEnv(&ActionMetadata{}, "", nil, nil)
	err := r.runCompositeRun(context.Background(), step, env)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "from-sh-direct")
}

func TestRunCompositeRun_CustomShellFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not available on windows")
	}

	// A custom shell template falls through to bash in current impl
	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	step := CompositeStep{
		Run:   "echo custom-shell-output",
		Shell: "some-custom-shell-{0}",
	}
	env := BuildActionEnv(&ActionMetadata{}, "", nil, nil)
	err := r.runCompositeRun(context.Background(), step, env)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "custom-shell-output")
}

func TestRunCompositeRun_EnvMerging(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	// Action-level env
	env := BuildActionEnv(&ActionMetadata{}, "", nil, map[string]string{
		"SHARED":      "from-action",
		"ACTION_ONLY": "present",
	})

	// Step-level env overrides SHARED
	step := CompositeStep{
		Run:   "echo $SHARED $ACTION_ONLY $STEP_ONLY",
		Shell: "bash",
		Env: map[string]string{
			"SHARED":    "from-step",
			"STEP_ONLY": "also-present",
		},
	}

	err := r.runCompositeRun(context.Background(), step, env)
	require.NoError(t, err)

	output := stdout.String()
	assert.Contains(t, output, "from-step")
	assert.Contains(t, output, "present")
	assert.Contains(t, output, "also-present")
}

func TestRunComposite_AlwaysConditionRunsAfterFailure(t *testing.T) {
	// In the current implementation, failure() returns false and always() returns true.
	// But the composite runner stops on first error regardless of conditions on later steps.
	// This test documents that behavior.
	if runtime.GOOS == "windows" {
		t.Skip("bash not available on windows")
	}

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "composite",
			Steps: []CompositeStep{
				{Name: "fail", Run: "exit 1", Shell: "bash"},
				{Name: "cleanup", If: "always()", Run: "echo cleanup-ran", Shell: "bash"},
			},
		},
	}

	err := r.runComposite(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	// The always() step doesn't run because the runner exits on failure
	assert.NotContains(t, stdout.String(), "cleanup-ran")
}

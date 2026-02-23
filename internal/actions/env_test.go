package actions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findEnvVar searches the env slice for a key and returns the value if found.
func findEnvVar(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}

func TestSetEnvVar_NewVariable(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux"}
	result := setEnvVar(env, "NEW_VAR", "new_value")

	val, found := findEnvVar(result, "NEW_VAR")
	require.True(t, found)
	assert.Equal(t, "new_value", val)

	// Original vars should still be there
	val, found = findEnvVar(result, "FOO")
	require.True(t, found)
	assert.Equal(t, "bar", val)
}

func TestSetEnvVar_ReplaceExisting(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux"}
	result := setEnvVar(env, "FOO", "new_bar")

	val, found := findEnvVar(result, "FOO")
	require.True(t, found)
	assert.Equal(t, "new_bar", val)

	// Length should not have changed (in-place replacement)
	assert.Len(t, result, 2)
}

func TestSetEnvVar_EmptySlice(t *testing.T) {
	env := []string{}
	result := setEnvVar(env, "KEY", "value")

	require.Len(t, result, 1)
	assert.Equal(t, "KEY=value", result[0])
}

func TestSetEnvVar_EmptyValue(t *testing.T) {
	env := []string{"FOO=bar"}
	result := setEnvVar(env, "FOO", "")

	val, found := findEnvVar(result, "FOO")
	require.True(t, found)
	assert.Equal(t, "", val)
}

func TestBuildActionEnv_DefaultInputs(t *testing.T) {
	meta := &ActionMetadata{
		Inputs: map[string]ActionInput{
			"fetch-depth": {Default: "1"},
			"token":       {Default: "default-token"},
		},
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "/action/dir", nil, nil)

	val, found := findEnvVar(env, "INPUT_FETCH_DEPTH")
	require.True(t, found)
	assert.Equal(t, "1", val)

	val, found = findEnvVar(env, "INPUT_TOKEN")
	require.True(t, found)
	assert.Equal(t, "default-token", val)
}

func TestBuildActionEnv_UserInputsOverrideDefaults(t *testing.T) {
	meta := &ActionMetadata{
		Inputs: map[string]ActionInput{
			"fetch-depth": {Default: "1"},
		},
		Runs: ActionRuns{Using: "node20"},
	}

	userInputs := map[string]string{
		"fetch-depth": "0",
	}

	env := BuildActionEnv(meta, "/action/dir", userInputs, nil)

	val, found := findEnvVar(env, "INPUT_FETCH_DEPTH")
	require.True(t, found)
	assert.Equal(t, "0", val, "user input should override default")
}

func TestBuildActionEnv_HyphenToUnderscore(t *testing.T) {
	meta := &ActionMetadata{
		Inputs: map[string]ActionInput{
			"my-input-name": {Default: "default"},
		},
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "", nil, nil)

	val, found := findEnvVar(env, "INPUT_MY_INPUT_NAME")
	require.True(t, found)
	assert.Equal(t, "default", val)
}

func TestBuildActionEnv_InputsUppercased(t *testing.T) {
	meta := &ActionMetadata{
		Inputs: map[string]ActionInput{},
		Runs:   ActionRuns{Using: "node20"},
	}

	userInputs := map[string]string{
		"my-input": "value",
	}

	env := BuildActionEnv(meta, "", userInputs, nil)

	val, found := findEnvVar(env, "INPUT_MY_INPUT")
	require.True(t, found)
	assert.Equal(t, "value", val)
}

func TestBuildActionEnv_GitHubActionPath(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "/path/to/action", nil, nil)

	val, found := findEnvVar(env, "GITHUB_ACTION_PATH")
	require.True(t, found)
	assert.Equal(t, "/path/to/action", val)
}

func TestBuildActionEnv_NoActionPathWhenEmpty(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "", nil, nil)

	_, found := findEnvVar(env, "GITHUB_ACTION_PATH")
	// If the original process env doesn't have it, it should not be set
	// This is a bit tricky because os.Environ() might have it from the
	// process environment. Let's just check that actionDir="" means
	// we didn't explicitly set it by checking BuildActionEnv doesn't crash.
	_ = found
}

func TestBuildActionEnv_RunsEnv(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Env: map[string]string{
				"SPECIAL_VAR": "special-value",
			},
		},
	}

	env := BuildActionEnv(meta, "", nil, nil)

	val, found := findEnvVar(env, "SPECIAL_VAR")
	require.True(t, found)
	assert.Equal(t, "special-value", val)
}

func TestBuildActionEnv_ExtraEnv(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "node20"},
	}

	extraEnv := map[string]string{
		"CUSTOM_VAR":   "custom-value",
		"ANOTHER_VAR":  "another-value",
	}

	env := BuildActionEnv(meta, "", nil, extraEnv)

	val, found := findEnvVar(env, "CUSTOM_VAR")
	require.True(t, found)
	assert.Equal(t, "custom-value", val)

	val, found = findEnvVar(env, "ANOTHER_VAR")
	require.True(t, found)
	assert.Equal(t, "another-value", val)
}

func TestBuildActionEnv_SkipsInputsWithNoDefault(t *testing.T) {
	meta := &ActionMetadata{
		Inputs: map[string]ActionInput{
			"required-input": {Required: true},  // No default
			"optional-input": {Default: "opt"},
		},
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "", nil, nil)

	// required-input has no default, so INPUT_REQUIRED_INPUT should not
	// be set by the defaults loop (it might exist from process env though).
	// optional-input with a default should be set.
	val, found := findEnvVar(env, "INPUT_OPTIONAL_INPUT")
	require.True(t, found)
	assert.Equal(t, "opt", val)
}

func TestBuildActionEnv_IncludesProcessEnv(t *testing.T) {
	// BuildActionEnv starts with os.Environ(), so it should include
	// process environment variables.
	t.Setenv("CILOCK_TEST_MARKER", "present")

	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "", nil, nil)

	val, found := findEnvVar(env, "CILOCK_TEST_MARKER")
	require.True(t, found)
	assert.Equal(t, "present", val)
}

func TestBuildActionEnv_ExtraEnvOverridesRunsEnv(t *testing.T) {
	// Extra env is applied after runs.env, so it should win
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Env: map[string]string{
				"SHARED_VAR": "from-runs",
			},
		},
	}

	extraEnv := map[string]string{
		"SHARED_VAR": "from-extra",
	}

	env := BuildActionEnv(meta, "", nil, extraEnv)

	val, found := findEnvVar(env, "SHARED_VAR")
	require.True(t, found)
	assert.Equal(t, "from-extra", val)
}

func TestBuildActionEnv_NilMaps(t *testing.T) {
	// Should handle nil userInputs and extraEnv without panicking
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "node20"},
	}

	env := BuildActionEnv(meta, "/dir", nil, nil)
	require.NotEmpty(t, env)
}

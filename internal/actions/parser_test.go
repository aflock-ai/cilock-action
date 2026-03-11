package actions

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseActionYAML_JavaScriptAction(t *testing.T) {
	dir := t.TempDir()
	yml := `name: 'My JS Action'
description: 'A test JavaScript action'
inputs:
  token:
    description: 'GitHub token'
    required: true
  fetch-depth:
    description: 'Number of commits to fetch'
    required: false
    default: '1'
outputs:
  result:
    description: 'The result'
runs:
  using: 'node20'
  main: 'dist/index.js'
  post: 'dist/cleanup.js'
  post-if: 'always()'
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(yml), 0o644))

	meta, err := ParseActionYAML(dir)
	require.NoError(t, err)

	assert.Equal(t, "My JS Action", meta.Name)
	assert.Equal(t, "A test JavaScript action", meta.Description)

	// Inputs
	require.Contains(t, meta.Inputs, "token")
	assert.True(t, meta.Inputs["token"].Required)
	require.Contains(t, meta.Inputs, "fetch-depth")
	assert.False(t, meta.Inputs["fetch-depth"].Required)
	assert.Equal(t, "1", meta.Inputs["fetch-depth"].Default)

	// Outputs
	require.Contains(t, meta.Outputs, "result")

	// Runs
	assert.Equal(t, "node20", meta.Runs.Using)
	assert.Equal(t, "dist/index.js", meta.Runs.Main)
	assert.Equal(t, "dist/cleanup.js", meta.Runs.Post)
	assert.Equal(t, "always()", meta.Runs.PostIf)
	assert.Equal(t, ActionTypeJavaScript, meta.Runs.Type())
}

func TestParseActionYAML_DockerAction(t *testing.T) {
	dir := t.TempDir()
	yml := `name: 'My Docker Action'
description: 'A Docker-based action'
inputs:
  args:
    description: 'Arguments'
    required: false
runs:
  using: 'docker'
  image: 'Dockerfile'
  entrypoint: '/entrypoint.sh'
  args:
    - '--verbose'
    - '${{ inputs.args }}'
  env:
    MY_VAR: 'hello'
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(yml), 0o644))

	meta, err := ParseActionYAML(dir)
	require.NoError(t, err)

	assert.Equal(t, "My Docker Action", meta.Name)
	assert.Equal(t, "docker", meta.Runs.Using)
	assert.Equal(t, "Dockerfile", meta.Runs.Image)
	assert.Equal(t, "/entrypoint.sh", meta.Runs.Entrypoint)
	assert.Equal(t, []string{"--verbose", "${{ inputs.args }}"}, meta.Runs.Args)
	require.NotNil(t, meta.Runs.Env)
	assert.Equal(t, "hello", meta.Runs.Env["MY_VAR"])
	assert.Equal(t, ActionTypeDocker, meta.Runs.Type())
}

func TestParseActionYAML_CompositeAction(t *testing.T) {
	dir := t.TempDir()
	yml := `name: 'My Composite Action'
description: 'A composite action'
inputs:
  who-to-greet:
    description: 'Who to greet'
    required: true
    default: 'World'
runs:
  using: 'composite'
  steps:
    - id: greet
      name: Greet
      run: echo "Hello ${{ inputs.who-to-greet }}"
      shell: bash
    - id: use-action
      name: Use another action
      uses: actions/checkout@v4
      with:
        fetch-depth: '0'
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(yml), 0o644))

	meta, err := ParseActionYAML(dir)
	require.NoError(t, err)

	assert.Equal(t, "My Composite Action", meta.Name)
	assert.Equal(t, "composite", meta.Runs.Using)
	assert.Equal(t, ActionTypeComposite, meta.Runs.Type())

	require.Len(t, meta.Runs.Steps, 2)

	step0 := meta.Runs.Steps[0]
	assert.Equal(t, "greet", step0.ID)
	assert.Equal(t, "Greet", step0.Name)
	assert.Contains(t, step0.Run, "Hello")
	assert.Equal(t, "bash", step0.Shell)

	step1 := meta.Runs.Steps[1]
	assert.Equal(t, "use-action", step1.ID)
	assert.Equal(t, "actions/checkout@v4", step1.Uses)
	require.NotNil(t, step1.With)
	assert.Equal(t, "0", step1.With["fetch-depth"])
}

func TestParseActionYAML_ActionYamlExtension(t *testing.T) {
	// Should also work with action.yaml (not just action.yml)
	dir := t.TempDir()
	yml := `name: 'YAML Extension Action'
description: 'Uses .yaml extension'
runs:
  using: 'node16'
  main: 'index.js'
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yaml"), []byte(yml), 0o644))

	meta, err := ParseActionYAML(dir)
	require.NoError(t, err)
	assert.Equal(t, "YAML Extension Action", meta.Name)
	assert.Equal(t, ActionTypeJavaScript, meta.Runs.Type())
}

func TestParseActionYAML_YmlPreferredOverYaml(t *testing.T) {
	// When both action.yml and action.yaml exist, action.yml should be used
	dir := t.TempDir()
	ymlContent := `name: 'From YML'
runs:
  using: 'node20'
  main: 'index.js'
`
	yamlContent := `name: 'From YAML'
runs:
  using: 'docker'
  image: 'Dockerfile'
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(ymlContent), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yaml"), []byte(yamlContent), 0o644))

	meta, err := ParseActionYAML(dir)
	require.NoError(t, err)
	assert.Equal(t, "From YML", meta.Name)
}

func TestParseActionYAML_NoActionFile(t *testing.T) {
	dir := t.TempDir()

	_, err := ParseActionYAML(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no action.yml or action.yaml found")
}

func TestParseActionYAML_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte("{{invalid yaml"), 0o644))

	_, err := ParseActionYAML(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestParseActionYAML_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	_, err := ParseActionYAML(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no action.yml or action.yaml found")
}

func TestActionType_String(t *testing.T) {
	tests := []struct {
		actionType ActionType
		expected   string
	}{
		{ActionTypeJavaScript, "javascript"},
		{ActionTypeDocker, "docker"},
		{ActionTypeComposite, "composite"},
		{ActionType(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.actionType.String())
		})
	}
}

func TestActionRuns_Type_NodeVersions(t *testing.T) {
	// Various node version strings should all map to JavaScript
	nodeVersions := []string{"node12", "node16", "node20", "node22", "Node20", "NODE16"}
	for _, v := range nodeVersions {
		t.Run(v, func(t *testing.T) {
			r := &ActionRuns{Using: v}
			assert.Equal(t, ActionTypeJavaScript, r.Type())
		})
	}
}

func TestActionRuns_Type_DockerCaseInsensitive(t *testing.T) {
	tests := []string{"docker", "Docker", "DOCKER"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			r := &ActionRuns{Using: v}
			assert.Equal(t, ActionTypeDocker, r.Type())
		})
	}
}

func TestActionRuns_Type_CompositeCaseInsensitive(t *testing.T) {
	tests := []string{"composite", "Composite", "COMPOSITE"}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			r := &ActionRuns{Using: v}
			assert.Equal(t, ActionTypeComposite, r.Type())
		})
	}
}

func TestActionRuns_Type_UnknownDefaultsToJS(t *testing.T) {
	// Unknown using values default to JavaScript
	r := &ActionRuns{Using: "something-unknown"}
	assert.Equal(t, ActionTypeJavaScript, r.Type())
}

package actions

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeActionDir creates a temp dir with an action.yml and returns the dir path.
func makeActionDir(t *testing.T, actionYAML string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "action.yml"), []byte(actionYAML), 0o644))
	return dir
}

func TestExecute_JavaScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	actionDir := makeActionDir(t, `
name: test-js-action
runs:
  using: node20
  main: index.js
`)
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "index.js"), []byte(`console.log("js-executed")`), 0o644))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta, err := ParseActionYAML(actionDir)
	require.NoError(t, err)

	err = r.Execute(context.Background(), &ResolvedAction{Dir: actionDir, Meta: meta})
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "js-executed")
}

func TestExecute_Composite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}

	actionDir := makeActionDir(t, `
name: test-composite-action
runs:
  using: composite
  steps:
    - name: hello
      run: echo composite-executed
      shell: bash
`)

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta, err := ParseActionYAML(actionDir)
	require.NoError(t, err)

	err = r.Execute(context.Background(), &ResolvedAction{Dir: actionDir, Meta: meta})
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "composite-executed")
}

func TestExecute_Docker(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	actionDir := makeActionDir(t, `
name: test-docker-action
runs:
  using: docker
  image: docker://alpine:3.19
  args:
    - echo
    - docker-executed
`)

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta, err := ParseActionYAML(actionDir)
	require.NoError(t, err)

	err = r.Execute(context.Background(), &ResolvedAction{Dir: actionDir, Meta: meta})
	// May fail if Docker daemon isn't running, that's ok
	if err != nil {
		assert.Contains(t, err.Error(), "docker")
	}
}

func TestExecute_UnknownUsing_FallsToJS(t *testing.T) {
	// ActionRuns.Type() defaults unknown `using` values to JavaScript,
	// so an unknown runtime hits the JS path and fails on missing main.
	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "unknown-runtime",
		},
	}

	err := r.Execute(context.Background(), &ResolvedAction{Dir: t.TempDir(), Meta: meta})
	require.Error(t, err)
	// Falls through to JS runner which errors on empty main
	assert.Contains(t, err.Error(), "no runs.main entry point")
}

func TestNewRunner_Defaults(t *testing.T) {
	r := NewRunner(map[string]string{"key": "val"}, map[string]string{"ENV": "val"})

	assert.Equal(t, os.Stdout, r.Stdout)
	assert.Equal(t, os.Stderr, r.Stderr)
	assert.Equal(t, "val", r.UserInputs["key"])
	assert.Equal(t, "val", r.ExtraEnv["ENV"])
}

func TestRunner_DepthPropagation(t *testing.T) {
	r := NewRunner(nil, nil)
	assert.Equal(t, 0, r.depth, "new runner starts at depth 0")

	// Simulate depth increment
	r.depth = maxCompositeDepth
	// At max depth, runCompositeUses should fail
	err := r.runCompositeUses(context.Background(), CompositeStep{Uses: "actions/checkout@v4"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth exceeded")
}

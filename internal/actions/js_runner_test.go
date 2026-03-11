package actions

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireNode(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available, skipping JS runner test")
	}
}

func TestRunJavaScript_MainOnly(t *testing.T) {
	requireNode(t)

	actionDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "index.js"), []byte(`console.log("main-output")`), 0o644))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "index.js",
		},
	}

	err := r.runJavaScript(context.Background(), meta, actionDir)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "main-output")
}

func TestRunJavaScript_PreMainPost(t *testing.T) {
	requireNode(t)

	actionDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "pre.js"), []byte(`console.log("pre-output")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "main.js"), []byte(`console.log("main-output")`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "post.js"), []byte(`console.log("post-output")`), 0o644))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "main.js",
			Pre:   "pre.js",
			Post:  "post.js",
		},
	}

	err := r.runJavaScript(context.Background(), meta, actionDir)
	require.NoError(t, err)

	output := stdout.String()
	// All three should have run
	assert.Contains(t, output, "pre-output")
	assert.Contains(t, output, "main-output")
	assert.Contains(t, output, "post-output")

	// Pre should come before main, main before post
	preIdx := bytes.Index([]byte(output), []byte("pre-output"))
	mainIdx := bytes.Index([]byte(output), []byte("main-output"))
	postIdx := bytes.Index([]byte(output), []byte("post-output"))
	assert.Less(t, preIdx, mainIdx, "pre should execute before main")
	assert.Less(t, mainIdx, postIdx, "main should execute before post")
}

func TestRunJavaScript_MissingMain(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "", // empty
		},
	}

	err := r.runJavaScript(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no runs.main entry point")
}

func TestRunJavaScript_MissingScript(t *testing.T) {
	requireNode(t)

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "nonexistent.js",
		},
	}

	err := r.runJavaScript(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "main step failed")
}

func TestRunJavaScript_ContextCancellation(t *testing.T) {
	requireNode(t)

	actionDir := t.TempDir()
	// Script that sleeps for a long time
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "slow.js"),
		[]byte(`setTimeout(() => {}, 60000)`), 0o644))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "slow.js",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := r.runJavaScript(ctx, meta, actionDir)
	require.Error(t, err)
}

func TestRunJavaScript_NonZeroExit(t *testing.T) {
	requireNode(t)

	actionDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "fail.js"),
		[]byte(`process.exit(42)`), 0o644))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "fail.js",
		},
	}

	err := r.runJavaScript(context.Background(), meta, actionDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "main step failed")
}

func TestRunJavaScript_EnvVars(t *testing.T) {
	requireNode(t)

	actionDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "env.js"),
		[]byte(`console.log(process.env.INPUT_MY_INPUT)`), 0o644))

	var stdout, stderr bytes.Buffer
	r := &Runner{
		UserInputs: map[string]string{"my-input": "test-value"},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
	}

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "node20",
			Main:  "env.js",
		},
	}

	err := r.runJavaScript(context.Background(), meta, actionDir)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "test-value")
}

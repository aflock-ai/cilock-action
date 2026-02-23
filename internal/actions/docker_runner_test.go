package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDockerRunArgs_DockerPrefixStripped(t *testing.T) {
	// The docker:// prefix is stripped in runDocker before calling runDockerContainer,
	// so by the time we hit buildDockerRunArgs the image should be plain.
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", []string{"FOO=bar"}, "/workspace")

	// Image should appear without docker:// prefix
	assert.Contains(t, args, "alpine:3.19")
	assert.NotContains(t, args, "docker://alpine:3.19")
}

func TestBuildDockerRunArgs_WorkspaceMount(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", nil, "/my/workspace")

	// Find the -v flag
	found := false
	for i, a := range args {
		if a == "-v" && i+1 < len(args) {
			if args[i+1] == "/my/workspace:/github/workspace" {
				found = true
			}
		}
	}
	assert.True(t, found, "workspace should be mounted at /github/workspace")

	// Working directory should be set
	foundW := false
	for i, a := range args {
		if a == "-w" && i+1 < len(args) {
			if args[i+1] == "/github/workspace" {
				foundW = true
			}
		}
	}
	assert.True(t, foundW, "working dir should be /github/workspace")
}

func TestBuildDockerRunArgs_CustomEntrypoint(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using:      "docker",
			Image:      "myimage:latest",
			Entrypoint: "/usr/bin/custom",
		},
	}
	args := buildDockerRunArgs(meta, "myimage:latest", nil, "/workspace")

	found := false
	for i, a := range args {
		if a == "--entrypoint" && i+1 < len(args) {
			assert.Equal(t, "/usr/bin/custom", args[i+1])
			found = true
		}
	}
	assert.True(t, found, "entrypoint should be passed via --entrypoint")
}

func TestBuildDockerRunArgs_NoEntrypoint(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", nil, "/workspace")

	for _, a := range args {
		assert.NotEqual(t, "--entrypoint", a, "no --entrypoint when not specified")
	}
}

func TestBuildDockerRunArgs_ArgsForwarded(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Image: "alpine:3.19",
			Args:  []string{"echo", "hello", "world"},
		},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", nil, "/workspace")

	// The image and its args should be at the end
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "alpine:3.19 echo hello world")
}

func TestBuildDockerRunArgs_EnvVarsPassed(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	env := []string{"FOO=bar", "BAZ=qux"}
	args := buildDockerRunArgs(meta, "alpine:3.19", env, "/workspace")

	// Each env var should be preceded by -e
	envCount := 0
	for i, a := range args {
		if a == "-e" && i+1 < len(args) {
			envCount++
		}
	}
	assert.Equal(t, 2, envCount)
}

func TestRunDocker_DockerfileDetection(t *testing.T) {
	// Test that images named "Dockerfile" or starting with "./" trigger the build path.
	// We can't actually run Docker here, but we verify the code path by checking
	// that runDocker returns a "docker build" related error (not "image not found").
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Image: "Dockerfile",
		},
	}

	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &strings.Builder{},
		Stderr:     &strings.Builder{},
	}

	// This will fail because there's no Dockerfile, but it should try to build
	err := r.runDocker(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build docker image")
}

func TestRunDocker_RelativeDockerfile(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Image: "./Dockerfile",
		},
	}

	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &strings.Builder{},
		Stderr:     &strings.Builder{},
	}

	err := r.runDocker(context.Background(), meta, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build docker image")
}

func TestRunDocker_DockerPrefixStripped(t *testing.T) {
	// When image has docker:// prefix but docker isn't available,
	// the prefix should be stripped before attempting to run
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Image: "docker://alpine:3.19",
		},
	}

	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &strings.Builder{},
		Stderr:     &strings.Builder{},
	}

	// This will error because docker isn't available or daemon isn't running,
	// but it should NOT try to build a Dockerfile (the docker:// prefix
	// means it's a pre-built image)
	err := r.runDocker(context.Background(), meta, t.TempDir())
	if err != nil {
		// Should be a "docker run" error, not a "docker build" error
		assert.NotContains(t, err.Error(), "failed to build docker image")
	}
}

func TestRunDocker_RelativeDockerfileInActionDir(t *testing.T) {
	// When image is a path that exists as a file in actionDir, trigger build.
	// This exercises the else-if branch in runDocker.
	tmpDir := t.TempDir()

	// Create an invalid Dockerfile that will fail to build
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "my.Dockerfile"), []byte("INVALID_INSTRUCTION\n"), 0o644))

	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Image: "my.Dockerfile", // not "Dockerfile" or "./", but file exists
		},
	}

	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &strings.Builder{},
		Stderr:     &strings.Builder{},
	}

	err := r.runDocker(context.Background(), meta, tmpDir)
	// Will fail at docker build since the Dockerfile is invalid
	if err != nil {
		assert.Contains(t, err.Error(), "failed to build docker image")
	}
}

func TestRunDocker_NonexistentRelativePath(t *testing.T) {
	// When image is a relative path that doesn't exist as a file, it should
	// be treated as a registry image (not trigger build path)
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using: "docker",
			Image: "nonexistent-image:latest",
		},
	}

	r := &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &strings.Builder{},
		Stderr:     &strings.Builder{},
	}

	err := r.runDocker(context.Background(), meta, t.TempDir())
	if err != nil {
		// Should NOT have tried to build
		assert.NotContains(t, err.Error(), "failed to build docker image")
	}
}

func TestBuildDockerRunArgs_NoArgs(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", nil, "/workspace")

	// Last element should be the image name (no extra args after it)
	assert.Equal(t, "alpine:3.19", args[len(args)-1])
}

func TestBuildDockerRunArgs_EmptyEnv(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", []string{}, "/workspace")

	// No -e flags should be present
	for _, a := range args {
		assert.NotEqual(t, "-e", a)
	}
}

func TestBuildDockerRunArgs_ComplexArgs(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using:      "docker",
			Image:      "myimage",
			Entrypoint: "/entrypoint.sh",
			Args:       []string{"--flag", "value", "--another=flag"},
		},
	}

	env := []string{"KEY1=val1", "KEY2=val2", "KEY3=val3"}
	args := buildDockerRunArgs(meta, "myimage", env, "/my/workspace")

	// Verify structure: run --rm --network bridge -e ... -v ... -w ... --entrypoint ... image args...
	assert.Equal(t, "run", args[0])
	assert.Equal(t, "--rm", args[1])

	// Count -e flags
	eCount := 0
	for _, a := range args {
		if a == "-e" {
			eCount++
		}
	}
	assert.Equal(t, 3, eCount)

	// Verify image and args at end
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "myimage --flag value --another=flag")
}

func TestBuildDockerRunArgs_BridgeNetwork(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{Using: "docker", Image: "alpine:3.19"},
	}
	args := buildDockerRunArgs(meta, "alpine:3.19", nil, "/workspace")

	// Should use bridge network (matching GitHub Actions behavior)
	found := false
	for i, a := range args {
		if a == "--network" && i+1 < len(args) {
			assert.Equal(t, "bridge", args[i+1])
			found = true
		}
	}
	assert.True(t, found, "should have --network bridge flag")
}

func TestBuildDockerConfig(t *testing.T) {
	meta := &ActionMetadata{
		Runs: ActionRuns{
			Using:      "docker",
			Image:      "myimage:latest",
			Entrypoint: "/entry.sh",
			Args:       []string{"--foo", "bar"},
		},
	}
	env := []string{"A=1", "B=2"}
	cfg := buildDockerConfig(meta, "myimage:latest", env, "/my/ws")

	assert.Equal(t, "myimage:latest", cfg.Image)
	assert.Equal(t, "bridge", cfg.Network)
	assert.Equal(t, "/my/ws", cfg.Workspace)
	assert.Equal(t, "/entry.sh", cfg.Entrypoint)
	assert.Equal(t, 2, cfg.EnvCount)
	assert.Equal(t, []string{"--foo", "bar"}, cfg.Args)
}

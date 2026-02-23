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

package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// runDocker executes a Docker-based GitHub Action.
func (r *Runner) runDocker(ctx context.Context, meta *ActionMetadata, actionDir string) error {
	image := meta.Runs.Image

	// Build from Dockerfile if image is "Dockerfile" or starts with "./"
	if image == "Dockerfile" || strings.HasPrefix(image, "./") {
		var err error
		image, err = r.buildDockerImage(ctx, actionDir, image)
		if err != nil {
			return fmt.Errorf("failed to build docker image: %w", err)
		}
	} else if !strings.HasPrefix(image, "docker://") {
		// If it's a relative path to a Dockerfile
		dockerfilePath := filepath.Join(actionDir, image)
		if _, err := os.Stat(dockerfilePath); err == nil {
			var err error
			image, err = r.buildDockerImage(ctx, actionDir, image)
			if err != nil {
				return fmt.Errorf("failed to build docker image: %w", err)
			}
		}
	}

	// Strip docker:// prefix if present
	image = strings.TrimPrefix(image, "docker://")

	return r.runDockerContainer(ctx, meta, image)
}

func (r *Runner) buildDockerImage(ctx context.Context, actionDir, dockerfilePath string) (string, error) {
	if dockerfilePath == "Dockerfile" {
		dockerfilePath = filepath.Join(actionDir, "Dockerfile")
	} else if !filepath.IsAbs(dockerfilePath) {
		dockerfilePath = filepath.Join(actionDir, dockerfilePath)
	}

	imageName := fmt.Sprintf("cilock-action-%d:latest", os.Getpid())

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, "-f", dockerfilePath, actionDir)
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker build failed: %w", err)
	}

	return imageName, nil
}

func (r *Runner) runDockerContainer(ctx context.Context, meta *ActionMetadata, image string) error {
	env := BuildActionEnv(meta, "", r.UserInputs, r.ExtraEnv)

	workspace := os.Getenv("GITHUB_WORKSPACE")
	if workspace == "" {
		var err error
		workspace, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
	}

	// Record config for attestation before executing
	cfg := buildDockerConfig(meta, image, env, workspace)
	r.DockerCfg = &cfg

	args := buildDockerRunArgs(meta, image, env, workspace)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr

	return cmd.Run()
}

// DockerConfig records the Docker container configuration used to run an action.
// This is captured for attestation auditability.
type DockerConfig struct {
	Image      string   `json:"image"`
	Args       []string `json:"args"`
	Network    string   `json:"network"`
	Workspace  string   `json:"workspace"`
	Entrypoint string   `json:"entrypoint,omitempty"`
	EnvCount   int      `json:"env_count"`
}

// buildDockerRunArgs constructs the arguments for `docker run` without executing it.
// Matches GitHub Actions container behavior: bridge network, workspace mount,
// Docker default capabilities (no --cap-drop/--cap-add, no --privileged).
func buildDockerRunArgs(meta *ActionMetadata, image string, env []string, workspace string) []string {
	args := []string{"run", "--rm"}

	// Use bridge network (matches GitHub Actions behavior — isolated per job,
	// not --network=host which would expose host network stack)
	args = append(args, "--network", "bridge")

	// Pass environment variables
	for _, e := range env {
		args = append(args, "-e", e)
	}

	// Mount workspace (matches GitHub's /__w volume mount pattern)
	args = append(args, "-v", workspace+":/github/workspace", "-w", "/github/workspace")

	// Set entrypoint if specified
	if meta.Runs.Entrypoint != "" {
		args = append(args, "--entrypoint", meta.Runs.Entrypoint)
	}

	args = append(args, image)

	// Add action args
	args = append(args, meta.Runs.Args...)

	return args
}

// buildDockerConfig captures the Docker configuration for attestation recording.
func buildDockerConfig(meta *ActionMetadata, image string, env []string, workspace string) DockerConfig {
	return DockerConfig{
		Image:      image,
		Args:       meta.Runs.Args,
		Network:    "bridge",
		Workspace:  workspace,
		Entrypoint: meta.Runs.Entrypoint,
		EnvCount:   len(env),
	}
}

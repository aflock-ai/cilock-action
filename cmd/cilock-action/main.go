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

// cilock-action is the Go binary for the cilock GitHub Action / GitLab CI template.
// It wraps commands and other GitHub Actions with rookery attestation.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/githubaction"

	// Import cicd preset plugins (includes github-action attestor)
	_ "github.com/aflock-ai/rookery/presets/cicd"

	"github.com/aflock-ai/cilock-action/internal/actions"
	cilockattest "github.com/aflock-ai/cilock-action/internal/attestation"
	"github.com/aflock-ai/cilock-action/internal/bypass"
	"github.com/aflock-ai/cilock-action/internal/config"
	"github.com/aflock-ai/cilock-action/internal/platform"
)

// Set by ldflags at build time.
var version = "dev"

func main() {
	// Register legacy witness aliases for backward compatibility
	attestation.RegisterLegacyAliases()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "::error::cilock-action: %v\n", err)
		cancel()
		os.Exit(1) //nolint:gocritic // intentional exit after error
	}
}

func run(ctx context.Context) error {
	plat := platform.Detect()
	fmt.Fprintf(os.Stderr, "cilock-action %s (platform: %s)\n", version, plat)

	// Parse config based on platform
	cfg, err := parseConfig(plat)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Check bypass mode
	if bypass.IsEnabled() {
		code, err := bypass.Run(ctx, cfg)
		if err != nil {
			return err
		}
		if code != 0 {
			os.Exit(code)
		}
		return nil
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Determine execution mode: command or action
	if cfg.ActionRef != "" {
		return runAction(ctx, cfg, plat)
	}
	return runCommand(ctx, cfg, plat)
}

// runCommand wraps a shell command with attestation.
func runCommand(ctx context.Context, cfg *config.Config, plat platform.Platform) error {
	command := []string{"sh", "-c", cfg.Command}

	result, err := cilockattest.Run(ctx, cfg, command)
	if err != nil {
		return err
	}

	return writeOutputs(plat, result)
}

// runAction downloads, wraps, and executes a GitHub Action with attestation.
// Uses the github-action attestor which executes the action during the
// attestation execute phase (between material and product collection).
func runAction(ctx context.Context, cfg *config.Config, plat platform.Platform) error {
	// Resolve the action (download + parse action.yml)
	resolved, err := actions.Resolve(ctx, cfg.ActionRef)
	if err != nil {
		return fmt.Errorf("failed to resolve action %s: %w", cfg.ActionRef, err)
	}

	// Create action runner
	runner := actions.NewRunner(cfg.ActionInputs, cfg.ActionEnv)

	// Check if the action ref is pinned to a full commit SHA
	pinned := isRefPinned(cfg.ActionRef)
	if !pinned {
		fmt.Fprintf(os.Stderr, "::warning::cilock-action: action ref %q is not pinned to a commit SHA — consider using owner/repo@FULL_SHA for supply chain security\n", cfg.ActionRef)
	}

	// Configure the github-action attestor with action metadata
	actionCfg := &cilockattest.ActionConfig{
		Ref:       resolved.Ref,
		Type:      resolved.Meta.Runs.Type().String(),
		Name:      resolved.Meta.Name,
		Dir:       resolved.Dir,
		Inputs:    cfg.ActionInputs,
		RefPinned: pinned,
		DockerConfigFn: func() *githubaction.DockerContainerConfig {
			if runner.DockerCfg == nil {
				return nil
			}
			return &githubaction.DockerContainerConfig{
				Image:      runner.DockerCfg.Image,
				Network:    runner.DockerCfg.Network,
				Workspace:  runner.DockerCfg.Workspace,
				Entrypoint: runner.DockerCfg.Entrypoint,
				EnvCount:   runner.DockerCfg.EnvCount,
				Args:       runner.DockerCfg.Args,
			}
		},
	}

	// Run attestation with the action execution happening during the execute phase.
	// The github-action attestor calls runner.Execute() between material and product
	// collection, so file-system side effects are captured properly.
	result, err := cilockattest.RunAction(ctx, cfg, actionCfg, func(execCtx context.Context) (int, error) {
		if execErr := runner.Execute(execCtx, resolved); execErr != nil {
			return 1, execErr
		}
		return 0, nil
	})
	if err != nil {
		return err
	}

	return writeOutputs(plat, result)
}

func writeOutputs(plat platform.Platform, result *cilockattest.Result) error {
	if result == nil {
		return nil
	}

	// Write git_oid output
	if len(result.GitOIDs) > 0 {
		if err := platform.SetOutput(plat, "git_oid", result.GitOIDs[0]); err != nil {
			return fmt.Errorf("failed to set git_oid output: %w", err)
		}
	}

	// Write attestation_file output
	if len(result.AttestationFiles) > 0 {
		if err := platform.SetOutput(plat, "attestation_file", result.AttestationFiles[0]); err != nil {
			return fmt.Errorf("failed to set attestation_file output: %w", err)
		}
	}

	// Write summary
	summary := buildSummary(result)
	if err := platform.WriteSummary(plat, summary); err != nil {
		fmt.Fprintf(os.Stderr, "::warning::failed to write summary: %v\n", err)
	}

	return nil
}

func buildSummary(result *cilockattest.Result) string {
	var sb strings.Builder
	sb.WriteString("### cilock-action Attestation\n\n")

	if len(result.GitOIDs) > 0 {
		sb.WriteString("| GitOID | Link |\n")
		sb.WriteString("|--------|------|\n")
		for _, oid := range result.GitOIDs {
			short := oid
			if len(short) > 12 {
				short = short[:12] + "..."
			}
			fmt.Fprintf(&sb, "| `%s` | [View](https://web.platform.testifysec.com/attestations/%s) |\n", short, oid)
		}
	}

	if len(result.AttestationFiles) > 0 {
		sb.WriteString("\n**Attestation files:**\n")
		for _, f := range result.AttestationFiles {
			fmt.Fprintf(&sb, "- `%s`\n", f)
		}
	}

	return sb.String()
}

// isRefPinned checks if an action ref is pinned to a full 40-character commit SHA.
// e.g., "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332" is pinned,
// but "actions/checkout@v4" is not.
func isRefPinned(ref string) bool {
	atIdx := strings.LastIndex(ref, "@")
	if atIdx < 0 {
		return false
	}
	sha := ref[atIdx+1:]
	if len(sha) != 40 {
		return false
	}
	_, err := hex.DecodeString(sha)
	return err == nil
}

func parseConfig(plat platform.Platform) (*config.Config, error) {
	switch plat {
	case platform.PlatformGitHub:
		return platform.ParseGitHub()
	case platform.PlatformGitLab:
		return platform.ParseGitLab()
	default:
		return nil, fmt.Errorf("CLI mode not yet implemented — use GitHub Actions or GitLab CI")
	}
}

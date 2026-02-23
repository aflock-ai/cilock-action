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
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aflock-ai/rookery/attestation"

	// Import cicd preset plugins
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
		os.Exit(1)
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
		code, err := bypass.Run(cfg)
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
func runAction(ctx context.Context, cfg *config.Config, plat platform.Platform) error {
	// Resolve the action (download + parse action.yml)
	resolved, err := actions.Resolve(ctx, cfg.ActionRef)
	if err != nil {
		return fmt.Errorf("failed to resolve action %s: %w", cfg.ActionRef, err)
	}

	// Create action runner
	runner := actions.NewRunner(cfg.ActionInputs, cfg.ActionEnv)

	// Build a command string that represents running the action.
	// This is what gets wrapped by attestation via commandrun.
	actionCommand := buildActionCommand(resolved, cfg)

	// Run attestation with the action execution as the "command"
	// For action wrapping, we don't use commandrun attestor — instead we run
	// the action directly and wrap the whole thing with attestation.
	result, err := runActionWithAttestation(ctx, cfg, runner, resolved, actionCommand)
	if err != nil {
		return err
	}

	return writeOutputs(plat, result)
}

// runActionWithAttestation executes the action within an attestation context.
func runActionWithAttestation(ctx context.Context, cfg *config.Config, runner *actions.Runner, resolved *actions.ResolvedAction, actionCommand []string) (*cilockattest.Result, error) {
	// For action wrapping, we run attestation with the action execution as the command.
	// The commandrun attestor will capture the action's execution.
	result, err := cilockattest.Run(ctx, cfg, actionCommand)
	if err != nil {
		// If attestation setup fails (e.g., signer error), still try to run the action
		// but return the error
		fmt.Fprintf(os.Stderr, "::warning::attestation failed: %v\n", err)

		// Run the action without attestation
		if execErr := runner.Execute(ctx, resolved); execErr != nil {
			return nil, fmt.Errorf("action execution failed: %w (attestation error: %v)", execErr, err)
		}
		return nil, err
	}

	return result, nil
}

// buildActionCommand creates a shell command that runs the resolved action.
// This is used by the commandrun attestor to capture execution metadata.
func buildActionCommand(resolved *actions.ResolvedAction, cfg *config.Config) []string {
	parts := []string{"cilock-action", "run-action", resolved.Ref}
	if len(cfg.ActionInputs) > 0 {
		var inputParts []string
		for k, v := range cfg.ActionInputs {
			inputParts = append(inputParts, fmt.Sprintf("%s=%s", k, v))
		}
		parts = append(parts, "--inputs", strings.Join(inputParts, ","))
	}
	return parts
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
			sb.WriteString(fmt.Sprintf("| `%s` | [View](https://web.platform.testifysec.com/attestations/%s) |\n", short, oid))
		}
	}

	if len(result.AttestationFiles) > 0 {
		sb.WriteString("\n**Attestation files:**\n")
		for _, f := range result.AttestationFiles {
			sb.WriteString(fmt.Sprintf("- `%s`\n", f))
		}
	}

	return sb.String()
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

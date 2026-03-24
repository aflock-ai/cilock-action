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
	"strings"
)

// runComposite executes a composite GitHub Action by running its steps sequentially.
func (r *Runner) runComposite(ctx context.Context, meta *ActionMetadata, actionDir string) error {
	env := BuildActionEnv(meta, actionDir, r.UserInputs, r.ExtraEnv)

	for i, step := range meta.Runs.Steps {
		// Evaluate if condition (simple string check — full expression evaluation is complex)
		if step.If != "" {
			shouldRun, warning := evaluateSimpleCondition(step.If)
			if warning != "" {
				fmt.Fprintf(r.Stderr, "::warning::cilock-action: %s\n", warning)
			}
			if !shouldRun {
				continue
			}
		}

		stepName := step.Name
		if stepName == "" {
			stepName = fmt.Sprintf("step-%d", i+1)
		}
		fmt.Fprintf(r.Stderr, "::group::%s\n", stepName)

		var err error
		if step.Uses != "" {
			err = r.runCompositeUses(ctx, step)
		} else if step.Run != "" {
			err = r.runCompositeRun(ctx, step, env)
		}

		fmt.Fprintf(r.Stderr, "::endgroup::\n")

		if err != nil {
			return fmt.Errorf("step %q failed: %w", stepName, err)
		}
	}

	return nil
}

// runCompositeUses handles a composite step that uses another action.
func (r *Runner) runCompositeUses(ctx context.Context, step CompositeStep) error {
	if r.depth >= maxCompositeDepth {
		return fmt.Errorf("composite action nesting depth exceeded maximum of %d", maxCompositeDepth)
	}

	// Resolve and run the nested action
	resolved, err := Resolve(ctx, step.Uses)
	if err != nil {
		return fmt.Errorf("failed to resolve nested action %s: %w", step.Uses, err)
	}

	// Create a sub-runner with step's inputs
	subRunner := NewRunner(step.With, step.Env)
	subRunner.Stdout = r.Stdout
	subRunner.Stderr = r.Stderr
	subRunner.depth = r.depth + 1

	return subRunner.Execute(ctx, resolved)
}

// runCompositeRun handles a composite step that runs a shell command.
func (r *Runner) runCompositeRun(ctx context.Context, step CompositeStep, env []string) error {
	shell := step.Shell
	if shell == "" {
		shell = "bash"
	}

	var shellCmd *exec.Cmd
	switch {
	case shell == "bash":
		shellCmd = exec.CommandContext(ctx, "bash", "-e", "-c", step.Run)
	case shell == "sh":
		shellCmd = exec.CommandContext(ctx, "sh", "-e", "-c", step.Run)
	case shell == "pwsh" || shell == "powershell":
		shellCmd = exec.CommandContext(ctx, "pwsh", "-Command", step.Run)
	case shell == "python":
		shellCmd = exec.CommandContext(ctx, "python", "-c", step.Run)
	default:
		// Custom shell template: {0} is replaced with a temp script file
		shellCmd = exec.CommandContext(ctx, "bash", "-e", "-c", step.Run)
	}

	// Merge step-level env into action env
	stepEnv := env
	for k, v := range step.Env {
		stepEnv = setEnvVar(stepEnv, k, v)
	}
	shellCmd.Env = stepEnv

	if step.WorkingDirectory != "" {
		shellCmd.Dir = step.WorkingDirectory
	}

	shellCmd.Stdout = r.Stdout
	shellCmd.Stderr = r.Stderr

	return shellCmd.Run()
}

// evaluateSimpleCondition handles basic if conditions.
// Returns (result, warning). Warning is non-empty if the expression couldn't be fully evaluated.
// Full GitHub Actions expression evaluation (${{ }}) is complex;
// we handle the most common patterns.
func evaluateSimpleCondition(condition string) (bool, string) {
	condition = strings.TrimSpace(condition)

	// Always/never
	if strings.EqualFold(condition, "always()") {
		return true, ""
	}
	if strings.EqualFold(condition, "false") {
		return false, ""
	}
	if strings.EqualFold(condition, "true") {
		return true, ""
	}

	// Check for success()/failure() — in our context, previous steps succeeded
	if strings.EqualFold(condition, "success()") {
		return true, ""
	}
	if strings.EqualFold(condition, "failure()") {
		return false, ""
	}

	// Environment variable checks
	if strings.Contains(condition, "env.") {
		// Basic env var existence check
		parts := strings.SplitN(condition, "env.", 2)
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[1])
			varName = strings.Trim(varName, "\"' }")
			return os.Getenv(varName) != "", ""
		}
	}

	// Default: skip unrecognized expressions (fail-safe)
	return false, fmt.Sprintf("unrecognized condition %q — skipping step (only always(), success(), failure(), true, false, env.* are supported)", condition)
}

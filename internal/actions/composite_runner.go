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
	"strconv"
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

// evaluateSimpleCondition handles basic if conditions from composite action steps.
// Returns (result, warning). Warning is non-empty if the expression couldn't be fully evaluated.
// Supports: always(), success(), failure(), true/false, env.*, and
// ${{ inputs.X == 'value' }} / ${{ inputs.X != 'value' }} expressions.
func evaluateSimpleCondition(condition string) (bool, string) {
	condition = strings.TrimSpace(condition)

	// Strip ${{ }} wrapper if present
	if strings.HasPrefix(condition, "${{") && strings.HasSuffix(condition, "}}") {
		condition = strings.TrimSpace(condition[3 : len(condition)-2])
	}

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

	// Comparison expressions must be evaluated BEFORE bare env.* checks,
	// otherwise env.X == 'value' gets intercepted by the env existence check.
	for _, op := range []string{"!=", "=="} {
		if strings.Contains(condition, op) {
			parts := strings.SplitN(condition, op, 2)
			if len(parts) == 2 {
				lhs := strings.TrimSpace(parts[0])
				rhs := strings.TrimSpace(parts[1])

				lhsVal, lhsUnsupported := resolveContextRef(lhs)
				rhsVal, rhsUnsupported := resolveContextRef(rhs)

				// Unsupported context refs (e.g. github.*) resolve to their raw
				// string, making any comparison meaningless. Short-circuit to
				// false so the step is safely skipped.
				if lhsUnsupported || rhsUnsupported {
					warning := fmt.Sprintf("condition %q uses unsupported context reference — step will be skipped (only inputs.*, env.*, and string literals are supported)", condition)
					return false, warning
				}

				if op == "==" {
					return lhsVal == rhsVal, ""
				}
				return lhsVal != rhsVal, ""
			}
		}
	}

	// Bare env.* existence check (no comparison operator)
	if strings.Contains(condition, "env.") {
		parts := strings.SplitN(condition, "env.", 2)
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[1])
			varName = strings.Trim(varName, "\"' })")
			return os.Getenv(varName) != "", ""
		}
	}

	// Default: skip unrecognized expressions (fail-safe)
	return false, fmt.Sprintf("unrecognized condition %q — skipping step (only always(), success(), failure(), true, false, env.*, inputs.* comparisons are supported)", condition)
}

// resolveContextRef resolves a GitHub Actions context reference to its value.
// Returns (resolved value, unsupported). unsupported is true when the ref uses
// a context we cannot resolve (e.g. github.*), in which case the raw ref string
// is returned as the value.
// Supports: inputs.X (via INPUT_X env var), env.X, string literals ('value'), and booleans.
func resolveContextRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)

	// Strip quotes from string literals
	if (strings.HasPrefix(ref, "'") && strings.HasSuffix(ref, "'")) ||
		(strings.HasPrefix(ref, "\"") && strings.HasSuffix(ref, "\"")) {
		return ref[1 : len(ref)-1], false
	}

	// inputs.X → INPUT_X env var (GitHub Actions converts input names to
	// uppercase with hyphens preserved: "skip-setup-trivy" → INPUT_SKIP-SETUP-TRIVY)
	if strings.HasPrefix(ref, "inputs.") {
		inputName := strings.TrimPrefix(ref, "inputs.")
		// Try both hyphenated (GitHub default) and underscored variants
		envKey := "INPUT_" + strings.ToUpper(inputName)
		if v := os.Getenv(envKey); v != "" {
			return v, false
		}
		// Only try the underscore variant if the name actually contains hyphens
		normalized := strings.ReplaceAll(inputName, "-", "_")
		if normalized != inputName {
			envKey = "INPUT_" + strings.ToUpper(normalized)
			if v := os.Getenv(envKey); v != "" {
				return v, false
			}
		}
		// Input not set — return empty string (matches GitHub Actions behavior
		// where unset inputs default to empty string)
		return "", false
	}

	// env.X → env var
	if strings.HasPrefix(ref, "env.") {
		return os.Getenv(strings.TrimPrefix(ref, "env.")), false
	}

	// Boolean literals — return as-is (these are valid expression values,
	// not unresolvable context references)
	lower := strings.ToLower(ref)
	if lower == "true" || lower == "false" {
		return lower, false
	}

	// Numeric literals — return as-is
	if _, err := strconv.ParseFloat(ref, 64); err == nil {
		return ref, false
	}

	// Dotted context refs (github.*, steps.*, etc.) — not yet supported
	return ref, true
}

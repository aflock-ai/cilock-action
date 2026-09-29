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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/aflock-ai/cilock-action/internal/scriptguard"
)

// Script capture modes, matching commandrun's ScriptCaptureMode values.
const (
	CaptureOff      = "off"
	CaptureIdentity = "identity"
	CaptureContent  = "content"
)

// StepRecord is what was recorded about one composite `run:` step.
type StepRecord struct {
	Index            int
	Name             string
	Action           string // nested action ref; empty for the wrapped action's own steps
	Shell            string
	WorkingDirectory string
	SHA256           string // hex digest of the bytes handed to the interpreter
	Script           string // those bytes, under content capture only
	ExitCode         int
	Skipped          bool
}

// StepRecorder collects StepRecords across a composite action and any
// composite actions it nests, and holds the guard that vets bodies before they
// are embedded.
type StepRecorder struct {
	// Mode is off, identity or content. Empty means identity.
	Mode string
	// Guard, when set and Mode is content, vets each body that will be
	// embedded. It runs before any step of the action executes.
	Guard func(step, body string, env []string) error
	Steps []StepRecord
}

// redactedMarker replaces a recorded text field the guard matched. It opens
// the field, so a reader can tell a redaction from text that merely says so.
const redactedMarker = "[redacted by the script-capture guard]"

func (rec *StepRecorder) embedsBodies() bool { return rec != nil && rec.Mode == CaptureContent }

func (rec *StepRecorder) record(r StepRecord) {
	if rec != nil {
		rec.Steps = append(rec.Steps, r)
	}
}

// scrub returns text as it will be recorded: unchanged, or redactedMarker when
// the guard finds a credential in it. Every author-supplied text field of a
// record (name, shell template, working directory, nested action ref) goes
// through it in every capture mode, because the record is signed into the
// attestation whatever the mode. A match redacts rather than refuses: the
// author did not ask for this text to be embedded. With no Guard configured
// the default guard applies, so a record is never written unvetted.
func (rec *StepRecorder) scrub(text string, env []string) string {
	if rec == nil || text == "" {
		return text
	}
	check := rec.Guard
	if check == nil {
		check = scriptguard.Check
	}
	if check("", text, env) != nil {
		return redactedMarker
	}
	return text
}

// stepRecord is the record of a run: step before it runs: its position and
// its author-supplied text, each field scrubbed.
func (r *Runner) stepRecord(i int, p plannedStep, env []string) StepRecord {
	return StepRecord{
		Index:            i,
		Name:             r.Recorder.scrub(p.name, env),
		Action:           r.Recorder.scrub(r.actionRef, env),
		Shell:            r.Recorder.scrub(effectiveShell(p.step.Shell), env),
		WorkingDirectory: r.Recorder.scrub(p.step.WorkingDirectory, env),
	}
}

type plannedStep struct {
	step CompositeStep
	name string
	run  bool
}

// runComposite executes a composite GitHub Action by running its steps sequentially.
func (r *Runner) runComposite(ctx context.Context, meta *ActionMetadata, actionDir string) error {
	env := r.actionEnv(meta, actionDir)

	// Decide every step's if: first. Conditions read only the process
	// environment, which no step can change, so deciding up front is the same
	// decision the loop would make, and it lets the guard see every body that
	// will run before the first one does.
	plan := make([]plannedStep, len(meta.Runs.Steps))
	for i, step := range meta.Runs.Steps {
		shouldRun := true
		if step.If != "" {
			var warning string
			shouldRun, warning = evaluateSimpleCondition(step.If)
			if warning != "" {
				fmt.Fprintf(r.Stderr, "::warning::cilock-action: %s\n", warning)
			}
		}
		name := step.Name
		if name == "" {
			name = fmt.Sprintf("step-%d", i+1)
		}
		plan[i] = plannedStep{step: step, name: name, run: shouldRun}
	}

	// The guard sees cilock's whole environment, not only the action's: the CI
	// OIDC credentials withheld from the action are still secrets a record
	// must not carry into the attestation.
	guardEnv := slices.Concat(os.Environ(), env)
	if r.Recorder.embedsBodies() && r.Recorder.Guard != nil {
		for _, p := range plan {
			if !p.run || p.step.Uses != "" || p.step.Run == "" {
				continue
			}
			if err := r.Recorder.Guard(p.name, p.step.Run, mergeStepEnv(guardEnv, p.step.Env)); err != nil {
				return err
			}
		}
	}

	for i, p := range plan {
		step := p.step
		isRun := step.Uses == "" && step.Run != ""
		if !p.run {
			if isRun {
				rec := r.stepRecord(i, p, mergeStepEnv(guardEnv, step.Env))
				rec.Skipped = true
				r.Recorder.record(rec)
			}
			continue
		}

		fmt.Fprintf(r.Stderr, "::group::%s\n", p.name)

		var err error
		if step.Uses != "" {
			err = r.runCompositeUses(ctx, step)
		} else if isRun {
			// One byte slice is digested, embedded and handed to the shell,
			// so all three describe the same bytes.
			body := []byte(step.Run)
			var code int
			code, err = r.execRunStep(ctx, step, body, env)
			rec := r.stepRecord(i, p, mergeStepEnv(guardEnv, step.Env))
			rec.ExitCode = code
			if r.Recorder != nil && r.Recorder.Mode != CaptureOff {
				sum := sha256.Sum256(body)
				rec.SHA256 = hex.EncodeToString(sum[:])
				if r.Recorder.embedsBodies() {
					rec.Script = string(body)
				}
			}
			r.Recorder.record(rec)
		}

		fmt.Fprintf(r.Stderr, "::endgroup::\n")

		if err != nil {
			return fmt.Errorf("step %q failed: %w", p.name, err)
		}
	}

	return nil
}

// mergeStepEnv overlays a step's env: on a copy of the action env.
func mergeStepEnv(env []string, stepEnv map[string]string) []string {
	merged := slices.Clone(env)
	for k, v := range stepEnv {
		merged = setEnvVar(merged, k, v)
	}
	return merged
}

func effectiveShell(shell string) string {
	if shell == "" {
		return "bash"
	}
	return shell
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
	subRunner := r.newSubRunner(step.With, step.Env)
	// Nested run: steps are recorded (and guarded) too, attributed to the
	// nested action. Its guard pass runs when the nested action starts.
	subRunner.Recorder = r.Recorder
	subRunner.actionRef = step.Uses

	return subRunner.Execute(ctx, resolved)
}

// runCompositeRun handles a composite step that runs a shell command.
func (r *Runner) runCompositeRun(ctx context.Context, step CompositeStep, env []string) error {
	_, err := r.execRunStep(ctx, step, []byte(step.Run), env)
	return err
}

// execRunStep hands body to the step's shell and returns the exit code: the
// process's status, or -1 when it did not start or was killed by a signal.
func (r *Runner) execRunStep(ctx context.Context, step CompositeStep, body []byte, env []string) (int, error) {
	var argv []string
	switch shell := effectiveShell(step.Shell); shell {
	case "bash":
		argv = []string{"bash", "-e", "-c", string(body)}
	case "sh":
		argv = []string{"sh", "-e", "-c", string(body)}
	case "pwsh", "powershell":
		argv = []string{"pwsh", "-Command", string(body)}
	case "python":
		argv = []string{"python", "-c", string(body)}
	default:
		// Custom shell template: the shell string is split on blanks and {0}
		// replaced by a temp file holding body.
		scriptPath, cleanup, err := customShellArgv(shell, body)
		if err != nil {
			return -1, err
		}
		defer cleanup()
		argv = scriptPath
	}

	shellCmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: runs the wrapped action's own declared shell
	shellCmd.Env = mergeStepEnv(env, step.Env)
	if step.WorkingDirectory != "" {
		shellCmd.Dir = step.WorkingDirectory
	}
	shellCmd.Stdout = r.Stdout
	shellCmd.Stderr = r.Stderr

	if err := shellCmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), err
		}
		return -1, err
	}
	return 0, nil
}

// customShellArgv writes body once to a 0600 temp file whose extension matches
// the shell, and returns the shell's argv with every {0} replaced by that path.
// The caller's digest is over the same body slice written here; the file is
// never re-read.
func customShellArgv(shell string, body []byte) ([]string, func(), error) {
	fields := strings.Fields(shell)
	if !strings.Contains(shell, "{0}") || len(fields) == 0 {
		return nil, nil, fmt.Errorf("shell %q is not a supported shell and has no {0} placeholder for the script path", shell)
	}

	f, err := os.CreateTemp(os.Getenv("RUNNER_TEMP"), "cilock-step-*"+scriptExtension(fields[0]))
	if err != nil {
		return nil, nil, fmt.Errorf("create step script: %w", err)
	}
	path := f.Name()
	cleanup := func() { _ = os.Remove(path) }
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		cleanup()
		return nil, nil, fmt.Errorf("write step script: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("write step script: %w", err)
	}

	for i, field := range fields {
		fields[i] = strings.ReplaceAll(field, "{0}", path)
	}
	return fields, cleanup, nil
}

// scriptExtension picks the temp script's extension from the shell program:
// some interpreters (pwsh, cmd) refuse a file without theirs.
func scriptExtension(program string) string {
	base := strings.ToLower(filepath.Base(program))
	switch {
	case strings.HasPrefix(base, "python"):
		return ".py"
	case base == "pwsh" || base == "powershell":
		return ".ps1"
	case base == "cmd":
		return ".cmd"
	case base == "node":
		return ".js"
	default:
		return ".sh"
	}
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

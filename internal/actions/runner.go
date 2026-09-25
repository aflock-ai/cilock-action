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
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation"
)

const maxCompositeDepth = 10

// Runner executes resolved GitHub Actions.
type Runner struct {
	// UserInputs are inputs provided by the user's workflow (action-inputs).
	UserInputs map[string]string
	// ExtraEnv are additional environment variables for the action (action-env).
	ExtraEnv map[string]string
	// Stdout and Stderr for action output.
	Stdout io.Writer
	Stderr io.Writer
	// DockerCfg is populated after a Docker action runs, capturing the container
	// configuration for attestation recording.
	DockerCfg *DockerConfig
	// InheritCIOIDC lets the wrapped action inherit the CI OIDC credentials
	// (ACTIONS_ID_TOKEN_REQUEST_*, CI_JOB_JWT*, SIGSTORE_ID_TOKEN, and any
	// CI-issued JWT). Off by default: an action holding them can mint the
	// signer's workflow identity (#9822). Set from the
	// inherit-ci-oidc-credentials input.
	InheritCIOIDC bool
	depth         int     // current composite action nesting depth
	parent        *Runner // the runner a nested `uses:` action was started from

	// childEnv accumulates what every environment built for this action (and
	// its nested actions) withheld, for the github-action attestation.
	childEnv *attestation.ChildEnvRecord
}

// ChildEnv returns what was done to the wrapped action's environment across
// every runner it used, or nil before any environment was built.
func (r *Runner) ChildEnv() *attestation.ChildEnvRecord {
	return r.root().childEnv
}

func (r *Runner) root() *Runner {
	for r.parent != nil {
		r = r.parent
	}
	return r
}

// actionEnv is the environment every runner hands the action: BuildActionEnv,
// minus the CI OIDC credentials unless InheritCIOIDC is set. The outcome is
// folded into the top-level runner's record. Runners must use this, never
// BuildActionEnv directly.
func (r *Runner) actionEnv(meta *ActionMetadata, actionDir string) []string {
	env, rec := attestation.ChildEnviron(BuildActionEnv(meta, actionDir, r.UserInputs, r.ExtraEnv), r.InheritCIOIDC)
	root := r.root()
	root.childEnv = root.childEnv.Merge(rec)
	return env
}

// newSubRunner starts a runner for a nested `uses:` action. It carries this
// runner's output streams and opt-out, and reports to this runner's record.
func (r *Runner) newSubRunner(with, env map[string]string) *Runner {
	sub := NewRunner(with, env)
	sub.Stdout = r.Stdout
	sub.Stderr = r.Stderr
	sub.InheritCIOIDC = r.InheritCIOIDC
	sub.depth = r.depth + 1
	sub.parent = r
	return sub
}

// NewRunner creates a Runner with defaults.
func NewRunner(userInputs, extraEnv map[string]string) *Runner {
	return &Runner{
		UserInputs: userInputs,
		ExtraEnv:   extraEnv,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}
}

// Execute runs the given action based on its type.
func (r *Runner) Execute(ctx context.Context, action *ResolvedAction) error {
	meta := action.Meta
	actionDir := action.Dir

	switch meta.Runs.Type() {
	case ActionTypeJavaScript:
		return r.runJavaScript(ctx, meta, actionDir)
	case ActionTypeDocker:
		return r.runDocker(ctx, meta, actionDir)
	case ActionTypeComposite:
		return r.runComposite(ctx, meta, actionDir)
	default:
		return fmt.Errorf("unsupported action type: %s (runs.using=%s)", meta.Runs.Type(), meta.Runs.Using)
	}
}

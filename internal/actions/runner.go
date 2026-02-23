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
	depth     int // current composite action nesting depth
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

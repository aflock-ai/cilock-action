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
	"os/exec"
	"path/filepath"
)

// runJavaScript executes a JavaScript (Node.js) GitHub Action.
func (r *Runner) runJavaScript(ctx context.Context, meta *ActionMetadata, actionDir string) error {
	if meta.Runs.Main == "" {
		return fmt.Errorf("javascript action has no runs.main entry point")
	}

	entryPoint := filepath.Join(actionDir, meta.Runs.Main)
	env := BuildActionEnv(meta, actionDir, r.UserInputs, r.ExtraEnv)

	// Run pre step if defined
	if meta.Runs.Pre != "" {
		preEntry := filepath.Join(actionDir, meta.Runs.Pre)
		if err := r.runNode(ctx, preEntry, env); err != nil {
			return fmt.Errorf("pre step failed: %w", err)
		}
	}

	// Run main step
	if err := r.runNode(ctx, entryPoint, env); err != nil {
		return fmt.Errorf("main step failed: %w", err)
	}

	// Run post step if defined
	if meta.Runs.Post != "" {
		postEntry := filepath.Join(actionDir, meta.Runs.Post)
		if err := r.runNode(ctx, postEntry, env); err != nil {
			return fmt.Errorf("post step failed: %w", err)
		}
	}

	return nil
}

func (r *Runner) runNode(ctx context.Context, entryPoint string, env []string) error {
	cmd := exec.CommandContext(ctx, "node", entryPoint)
	cmd.Env = env
	cmd.Stdout = r.Stdout
	cmd.Stderr = r.Stderr
	return cmd.Run()
}

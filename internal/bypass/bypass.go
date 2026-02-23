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

// Package bypass implements CILOCK_BYPASS mode, which skips attestation
// and runs the command directly.
package bypass

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aflock-ai/cilock-action/internal/config"
)

// IsEnabled checks if bypass mode is active via CILOCK_BYPASS env var.
func IsEnabled() bool {
	return strings.EqualFold(os.Getenv("CILOCK_BYPASS"), "true")
}

// Run executes the command directly without attestation.
// Returns the exit code from the command.
func Run(cfg *config.Config) (int, error) {
	if cfg.Command == "" {
		fmt.Fprintln(os.Stderr, "cilock-action: bypass mode active, no command to run")
		return 0, nil
	}

	fmt.Fprintln(os.Stderr, "cilock-action: CILOCK_BYPASS is set, running command without attestation")

	cmd := exec.Command("sh", "-c", cfg.Command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Dir = cfg.WorkingDir

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("failed to run command: %w", err)
	}
	return 0, nil
}

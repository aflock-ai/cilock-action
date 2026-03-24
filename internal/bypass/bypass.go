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
// and runs the command directly. Bypass is intended only as a downtime
// backup — a 20-second penalty delay is enforced to discourage routine use.
package bypass

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aflock-ai/cilock-action/internal/config"
)

// PenaltyDelay is the delay enforced when bypass mode is used.
// This discourages routine use — bypass is for downtime backup only.
var PenaltyDelay = 20 * time.Second

// IsEnabled checks if bypass mode is active via CILOCK_BYPASS env var.
func IsEnabled() bool {
	return strings.EqualFold(os.Getenv("CILOCK_BYPASS"), "true")
}

// Run executes the command directly without attestation.
// Emits audit warnings and enforces a penalty delay to discourage use.
// Returns the exit code from the command.
func Run(ctx context.Context, cfg *config.Config) (int, error) {
	// Emit loud audit trail — visible in GitHub Actions annotations
	fmt.Fprintln(os.Stderr, "::warning::CILOCK BYPASS ACTIVE — attestation is disabled. This should only be used during system downtime.")
	fmt.Fprintln(os.Stderr, "::warning::CILOCK BYPASS — no attestation will be generated for this step. Audit trail: CILOCK_BYPASS=true was set in environment.")
	fmt.Fprintf(os.Stderr, "::notice::cilock-action: bypass penalty — waiting %s to discourage routine bypass usage\n", PenaltyDelay)

	// Enforce penalty delay
	fmt.Fprintf(os.Stderr, "cilock-action: bypass mode active — enforcing %s penalty delay...\n", PenaltyDelay)
	time.Sleep(PenaltyDelay)
	fmt.Fprintln(os.Stderr, "cilock-action: penalty delay complete, proceeding without attestation")

	if cfg.Command == "" {
		fmt.Fprintln(os.Stderr, "cilock-action: bypass mode active, no command to run")
		return 0, nil
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", cfg.Command)
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

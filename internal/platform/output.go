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

package platform

import (
	"fmt"
	"os"
	"strings"
)

// SetOutput writes an output key=value pair for the current CI platform.
func SetOutput(platform Platform, key, value string) error {
	switch platform {
	case PlatformGitHub:
		return setGitHubOutput(key, value)
	case PlatformGitLab:
		return setGitLabOutput(key, value)
	default:
		fmt.Printf("%s=%s\n", key, value)
		return nil
	}
}

// WriteSummary appends markdown content to the job summary (GitHub only).
func WriteSummary(platform Platform, markdown string) error {
	if platform != PlatformGitHub {
		return nil
	}
	summaryFile := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryFile == "" {
		return nil
	}
	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_STEP_SUMMARY: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, markdown)
	return err
}

func setGitHubOutput(key, value string) error {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		// Fallback to deprecated ::set-output command
		fmt.Printf("::set-output name=%s::%s\n", key, value)
		return nil
	}
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_OUTPUT: %w", err)
	}
	defer f.Close()

	// Handle multiline values with heredoc delimiter
	if strings.Contains(value, "\n") {
		_, err = fmt.Fprintf(f, "%s<<EOF\n%s\nEOF\n", key, value)
	} else {
		_, err = fmt.Fprintf(f, "%s=%s\n", key, value)
	}
	return err
}

func setGitLabOutput(key, value string) error {
	// GitLab uses dotenv artifacts for outputs
	dotenvFile := os.Getenv("CILOCK_DOTENV_FILE")
	if dotenvFile == "" {
		dotenvFile = "cilock.env"
	}
	f, err := os.OpenFile(dotenvFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open dotenv file: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s=%s\n", key, value)
	return err
}

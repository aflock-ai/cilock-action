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
	"os"
	"strings"
)

// BuildActionEnv creates the environment variable slice for running an action.
// It includes: current process env, INPUT_* from action defaults + user overrides,
// GITHUB_ACTION_PATH, and any additional env vars.
func BuildActionEnv(meta *ActionMetadata, actionDir string, userInputs, extraEnv map[string]string) []string {
	env := os.Environ()

	// Set INPUT_* variables from action defaults
	for name, input := range meta.Inputs {
		envKey := "INPUT_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		if input.Default != "" {
			env = setEnvVar(env, envKey, input.Default)
		}
	}

	// Override with user-provided inputs
	for name, value := range userInputs {
		envKey := "INPUT_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		env = setEnvVar(env, envKey, value)
	}

	// Set GITHUB_ACTION_PATH
	if actionDir != "" {
		env = setEnvVar(env, "GITHUB_ACTION_PATH", actionDir)
	}

	// Set any additional env vars from action.yml runs.env
	if meta.Runs.Env != nil {
		for k, v := range meta.Runs.Env {
			env = setEnvVar(env, k, v)
		}
	}

	// Set extra env vars from user
	for k, v := range extraEnv {
		env = setEnvVar(env, k, v)
	}

	return env
}

// setEnvVar sets or replaces an environment variable in the env slice.
func setEnvVar(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

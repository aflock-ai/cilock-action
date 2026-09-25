// Copyright 2026 TestifySec, Inc.
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

// jade:ring local

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// #9822: neither a wrapped command nor a wrapped action may inherit the job's
// OIDC token request credential unless the workflow opts out with
// `inherit-ci-oidc-credentials`, and the attestation records which it was.

// childEnvFromOutfile returns the childEnv record of the attestation of the
// given type in the (unsigned, test-mode) envelope. command-run carries it at
// _meta.childEnv, github-action at childEnv.
func childEnvFromOutfile(t *testing.T, outfile, typeFragment string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(outfile)
	require.NoError(t, err)
	var env struct {
		Payload string `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(raw, &env))
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	require.NoError(t, err)
	var stmt struct {
		Predicate struct {
			Attestations []struct {
				Type        string          `json:"type"`
				Attestation json.RawMessage `json:"attestation"`
			} `json:"attestations"`
		} `json:"predicate"`
	}
	require.NoError(t, json.Unmarshal(payload, &stmt))
	var types []string
	for _, a := range stmt.Predicate.Attestations {
		types = append(types, a.Type)
		if !strings.Contains(a.Type, typeFragment) {
			continue
		}
		var body struct {
			ChildEnv map[string]any `json:"childEnv"`
			Meta     struct {
				ChildEnv map[string]any `json:"childEnv"`
			} `json:"_meta"`
		}
		require.NoError(t, json.Unmarshal(a.Attestation, &body))
		if body.Meta.ChildEnv != nil {
			return body.Meta.ChildEnv
		}
		return body.ChildEnv
	}
	t.Fatalf("no %s attestation among %v", typeFragment, types)
	return nil
}

func setCIOIDCForRun(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/?x=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token-0123456789")
	// Archivista is disabled; keep its OIDC auto-detection off too.
	t.Setenv("INPUT_ARCHIVISTA_OIDC", "false")
	dump := filepath.Join(t.TempDir(), "child-env.txt")
	t.Setenv("CILOCK_TEST_ENV_DUMP", dump)
	return dump
}

func childSaw(t *testing.T, dump, name string) bool {
	t.Helper()
	raw, err := os.ReadFile(dump)
	require.NoError(t, err, "the wrapped step did not run")
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, name+"=") {
			return true
		}
	}
	return false
}

func runCommandMode(t *testing.T, inherit string) (dump, outfile string) {
	t.Helper()
	attestation.RegisterLegacyAliases()
	setupGitHubEnvForRun(t)
	dump = setCIOIDCForRun(t)
	t.Setenv("INPUT_COMMAND", `env > "$CILOCK_TEST_ENV_DUMP"`)
	t.Setenv("INPUT_ACTION_REF", "")
	t.Setenv("INPUT_STEP", "oidc-scrub")
	t.Setenv("INPUT_INHERIT_CI_OIDC_CREDENTIALS", inherit)
	outfile = filepath.Join(t.TempDir(), "attestation.json")
	t.Setenv("INPUT_OUTFILE", outfile)
	setupGitHubOutputFiles(t)
	require.NoError(t, run(context.Background()))
	return dump, outfile
}

func TestCommandModeWithholdsCIOIDCCredentials(t *testing.T) {
	dump, outfile := runCommandMode(t, "")
	require.False(t, childSaw(t, dump, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"), "wrapped command saw the token request credential")
	require.False(t, childSaw(t, dump, "ACTIONS_ID_TOKEN_REQUEST_URL"))
	rec := childEnvFromOutfile(t, outfile, "command-run")
	require.Equal(t, "scrubbed", rec["ciOidcCredentials"], "%v", rec)
}

func TestCommandModeOptOutIsRecorded(t *testing.T) {
	dump, outfile := runCommandMode(t, "true")
	require.True(t, childSaw(t, dump, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"), "opt-out set but the command did not see the credential")
	rec := childEnvFromOutfile(t, outfile, "command-run")
	require.Equal(t, "inherited", rec["ciOidcCredentials"], "%v", rec)
}

// createEnvDumpAction is a composite action whose only step writes its
// environment to $CILOCK_TEST_ENV_DUMP.
func createEnvDumpAction(t *testing.T) string {
	t.Helper()
	baseDir := t.TempDir()
	actionDir := filepath.Join(baseDir, "test-org", "dump-env", "v1")
	require.NoError(t, os.MkdirAll(actionDir, 0o755))
	yaml := "name: Dump env\nruns:\n  using: composite\n  steps:\n    - run: env > \"$CILOCK_TEST_ENV_DUMP\"\n      shell: bash\n"
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(yaml), 0o644))
	return baseDir
}

func runActionMode(t *testing.T, inherit string) (dump, outfile string) {
	t.Helper()
	attestation.RegisterLegacyAliases()
	setupGitHubEnvForRun(t)
	dump = setCIOIDCForRun(t)
	t.Setenv("CILOCK_LOCAL_ACTION_DIR", createEnvDumpAction(t))
	t.Setenv("INPUT_ACTION_REF", "test-org/dump-env@v1")
	t.Setenv("INPUT_COMMAND", "")
	t.Setenv("INPUT_STEP", "oidc-scrub-action")
	t.Setenv("INPUT_INHERIT_CI_OIDC_CREDENTIALS", inherit)
	outfile = filepath.Join(t.TempDir(), "attestation.json")
	t.Setenv("INPUT_OUTFILE", outfile)
	setupGitHubOutputFiles(t)
	require.NoError(t, run(context.Background()))
	return dump, outfile
}

func TestActionModeWithholdsCIOIDCCredentials(t *testing.T) {
	dump, outfile := runActionMode(t, "")
	require.False(t, childSaw(t, dump, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"), "wrapped action saw the token request credential")
	require.False(t, childSaw(t, dump, "ACTIONS_ID_TOKEN_REQUEST_URL"))
	rec := childEnvFromOutfile(t, outfile, "github-action")
	require.Equal(t, "scrubbed", rec["ciOidcCredentials"], "%v", rec)
	require.ElementsMatch(t, []any{"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"}, rec["scrubbed"])
}

func TestActionModeOptOutIsRecorded(t *testing.T) {
	dump, outfile := runActionMode(t, "true")
	require.True(t, childSaw(t, dump, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"), "opt-out set but the action did not see the credential")
	rec := childEnvFromOutfile(t, outfile, "github-action")
	require.Equal(t, "inherited", rec["ciOidcCredentials"], "%v", rec)
}

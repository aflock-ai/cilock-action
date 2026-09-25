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

package actions

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #9822: an action wrapped by cilock-action must not inherit the job's OIDC
// token request credential, or it can mint the signer's workflow identity.

func setCIOIDCEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/?x=1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token-0123456789")
	t.Setenv("CILOCK_ACTION_SCRUB_CONTROL", "still-here")
}

func envNames(env []string) map[string]bool {
	out := map[string]bool{}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		out[name] = true
	}
	return out
}

// actionEnv is the one place every runner (JavaScript, Docker, composite)
// gets its environment, so the scrub is tested there, including a credential
// a workflow passes in explicitly through action-env.
func TestActionEnvWithholdsCIOIDCCredentialsByDefault(t *testing.T) {
	setCIOIDCEnv(t)
	r := NewRunner(nil, map[string]string{"SIGSTORE_ID_TOKEN": "explicitly-passed"})
	meta := &ActionMetadata{Runs: ActionRuns{Using: "node20", Main: "index.js"}}

	names := envNames(r.actionEnv(meta, t.TempDir()))
	for _, n := range []string{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "SIGSTORE_ID_TOKEN"} {
		assert.False(t, names[n], "wrapped action received %s", n)
	}
	assert.True(t, names["CILOCK_ACTION_SCRUB_CONTROL"], "the scrub removed more than CI OIDC credentials")
	assert.True(t, names["GITHUB_ACTION_PATH"], "the action's own env must survive")

	rec := r.ChildEnv()
	require.NotNil(t, rec)
	assert.Equal(t, attestation.ChildEnvCIOIDCScrubbed, rec.CIOIDCCredentials)
	assert.Equal(t, []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "SIGSTORE_ID_TOKEN"}, rec.Scrubbed)
}

func TestActionEnvInheritsWithOptOut(t *testing.T) {
	setCIOIDCEnv(t)
	r := NewRunner(nil, nil)
	r.InheritCIOIDC = true
	meta := &ActionMetadata{Runs: ActionRuns{Using: "node20", Main: "index.js"}}

	names := envNames(r.actionEnv(meta, t.TempDir()))
	assert.True(t, names["ACTIONS_ID_TOKEN_REQUEST_URL"])
	assert.True(t, names["ACTIONS_ID_TOKEN_REQUEST_TOKEN"])
	require.NotNil(t, r.ChildEnv())
	assert.Equal(t, attestation.ChildEnvCIOIDCInherited, r.ChildEnv().CIOIDCCredentials)
}

// End to end through a composite `run:` step: the shell never sees the token.
func TestCompositeStepDoesNotSeeCIOIDCCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	setCIOIDCEnv(t)
	var stdout, stderr bytes.Buffer
	r := NewRunner(nil, nil)
	r.Stdout, r.Stderr = &stdout, &stderr
	meta := &ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: []CompositeStep{
		{Name: "dump", Run: "env", Shell: "bash"},
	}}}
	require.NoError(t, r.runComposite(context.Background(), meta, t.TempDir()))
	assert.NotContains(t, stdout.String(), "ACTIONS_ID_TOKEN_REQUEST")
	assert.Contains(t, stdout.String(), "CILOCK_ACTION_SCRUB_CONTROL=still-here")
}

// A nested `uses:` action runs in a sub-runner. It must carry the parent's
// opt-out decision, and what it withheld must reach the parent's record.
func TestSubRunnerCarriesOptOutAndReportsToParent(t *testing.T) {
	setCIOIDCEnv(t)
	meta := &ActionMetadata{Runs: ActionRuns{Using: "node20", Main: "index.js"}}

	parent := NewRunner(nil, nil)
	sub := parent.newSubRunner(nil, map[string]string{"SIGSTORE_ID_TOKEN": "nested"})
	assert.False(t, sub.InheritCIOIDC)
	names := envNames(sub.actionEnv(meta, t.TempDir()))
	assert.False(t, names["SIGSTORE_ID_TOKEN"])
	require.NotNil(t, parent.ChildEnv(), "the nested runner's record must reach the parent")
	assert.Contains(t, parent.ChildEnv().Scrubbed, "SIGSTORE_ID_TOKEN")

	inheriting := NewRunner(nil, nil)
	inheriting.InheritCIOIDC = true
	assert.True(t, inheriting.newSubRunner(nil, nil).InheritCIOIDC)
}

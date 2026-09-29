// jade:ring local

package scriptguard

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each credential shape is refused, and the refusal names the rule and the
// step but never the matched bytes.
func TestScanRefusesEveryCredentialShape(t *testing.T) {
	for _, tc := range []struct {
		rule   string
		secret string
	}{
		{"github-token", "ghp_" + strings.Repeat("A1b2", 9)},
		{"github-token", "gho_" + strings.Repeat("Z9y8", 9)},
		{"github-token", "ghs_" + strings.Repeat("Qq11", 9)},
		{"github-token", "ghu_" + strings.Repeat("Ww22", 9)},
		{"github-token", "ghr_" + strings.Repeat("Rr33", 9)}, // refresh token
		{"github-pat", "github_pat_" + strings.Repeat("Ab1_", 20)},
		{"aws-access-key-id", "AKIA" + "ABCDEFGHIJKLMNOP"},
		{"aws-access-key-id", "ASIA" + "ABCDEFGHIJKLMNOP"}, // temporary (STS) key
		// Every xox?- family member: bot, user, app, refresh, legacy
		// workspace, browser session, cookie and the rotating refresh token.
		{"slack-token", "xoxb-1234567890-abcdefghij"},
		{"slack-token", "xoxp-1234567890-abcdefghij"},
		{"slack-token", "xoxa-1234567890-abcdefghij"},
		{"slack-token", "xoxr-1234567890-abcdefghij"},
		{"slack-token", "xoxs-1234567890-abcdefghij"},
		{"slack-token", "xoxc-1234567890-abcdefghij"},
		{"slack-token", "xoxd-1234567890-abcdefghij"},
		{"slack-token", "xoxe-1-abcdefghij1234567890"},
		{"slack-token", "xapp-1-A0123456789-abcdefghij"}, // app-level token
		{"private-key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"private-key", "-----BEGIN PRIVATE KEY-----"},
	} {
		t.Run(tc.rule+"/"+tc.secret[:6], func(t *testing.T) {
			body := "#!/bin/sh\ncurl -H 'x: " + tc.secret + "' https://example.invalid\n"
			err := Check("deploy step", body, nil)
			require.Error(t, err)
			msg := err.Error()
			assert.Contains(t, msg, tc.rule)
			assert.Contains(t, msg, "deploy step")
			assert.NotContains(t, msg, tc.secret)
			assert.Contains(t, msg, "script-capture: identity", "the refusal names the per-step escape hatch")
			assert.Contains(t, msg, "env:", "the refusal names the safe spelling")
		})
	}
}

// A value of a sensitive variable is refused wherever it appears; the same
// bytes in a variable the list does not name pass.
func TestScanSensitiveEnvValues(t *testing.T) {
	const value = "s3cr3t-opaque-value"
	body := "echo " + value + "\n"

	for _, name := range []string{"GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "MY_DEPLOY_PASSWORD", "npm_token"} {
		err := Check("build", body, []string{"UNRELATED=x", name + "=" + value})
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "sensitive-env:"+name)
		assert.NotContains(t, err.Error(), value)
	}

	assert.NoError(t, Check("build", body, []string{"RELEASE_NOTES=" + value}),
		"a non-sensitive variable holding the same text is not a secret")
	assert.NoError(t, Check("build", "echo short\n", []string{"GITHUB_TOKEN=short"}),
		"values under 8 bytes are not matched: they would match ordinary words")
	assert.NoError(t, Check("build", "echo ok\n", []string{"GITHUB_TOKEN=" + value}),
		"a sensitive variable whose value is absent from the body is fine")
	assert.NoError(t, Check("build", "echo $GITHUB_TOKEN\n", []string{"GITHUB_TOKEN=" + value}),
		"referencing the variable by name is the safe spelling")
}

// The directories every runner exports match the list's `*PAT*` and `*PWD*`
// globs by accident. Scripts spell those directories out, so they must not
// refuse the step; the credentials those globs exist for still do.
func TestScanIgnoresPathLikeRunnerVariables(t *testing.T) {
	const dir = "/home/runner/work/repo/repo"
	body := "cd " + dir + " && make\n"
	for _, name := range []string{"PATH", "GITHUB_PATH", "GITHUB_ACTION_PATH", "PWD", "OLDPWD", "GOPATH"} {
		assert.NoError(t, Check("build", body, []string{name + "=" + dir}), name)
	}
	for _, name := range []string{"GITHUB_PAT", "DEPLOY_PAT", "SECRET_PATH", "DB_PWD"} {
		assert.Error(t, Check("build", body, []string{name + "=" + dir}), name)
	}
}

func TestScanCleanBodyPasses(t *testing.T) {
	assert.NoError(t, Check("build", "#!/bin/sh\nmake all\n", []string{"HOME=/home/runner"}))
	// Prose that names a prefix, or a word outside a family, is not a credential.
	for _, body := range []string{
		"echo 'tokens start with ghp_ or ghr_'\n",
		"echo xoxo-hugs xoxz-thing\n",
		"echo 'keys start with AKIA or ASIA'\n",
		"echo xapp-name\n",
	} {
		assert.NoError(t, Check("build", body, nil), "%q", body)
	}
}

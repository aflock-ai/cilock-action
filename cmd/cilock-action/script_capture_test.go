// jade:ring local

package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptCaptureFixtureRepo moves the test into a fresh single-commit git
// repository with an isolated git configuration and returns its root. run()
// attests with the git attestor from the working directory, which refuses a
// subdirectory of a worktree, so these tests must not depend on the developer
// checkout they happen to run in. files are written before the commit.
func scriptCaptureFixtureRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	require.NoError(t, os.WriteFile(filepath.Join(root, "file.txt"), []byte("fixture\n"), 0o644))
	for name, body := range files {
		p := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o700)) //nolint:gosec // test fixture scripts
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"add", "."},
		{"-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "-q", "-m", "fixture"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	t.Chdir(root)
	return root
}

// scriptCaptureRunEnv sets the GitHub inputs for a local run() with no
// external services, and returns the outfile path.
func scriptCaptureRunEnv(t *testing.T, step string) string {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("INPUT_ENABLE_SIGSTORE", "false")
	t.Setenv("INPUT_ENABLE_ARCHIVISTA", "false")
	t.Setenv("INPUT_ATTESTATIONS", "environment git")
	t.Setenv("INPUT_STEP", step)
	t.Setenv("INPUT_SCRIPT-CAPTURE", "")
	t.Setenv("INPUT_SCRIPT_CAPTURE", "")
	outfile := filepath.Join(t.TempDir(), "attestation.json")
	t.Setenv("INPUT_OUTFILE", outfile)
	setupGitHubOutputFiles(t)
	return outfile
}

// readCollection decodes the unsigned envelope run() wrote.
func readCollection(t *testing.T, path string) attestation.Collection {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))
	var coll attestation.Collection
	require.NoError(t, json.Unmarshal(stmt.Predicate, &coll))
	return coll
}

func commandRunOf(t *testing.T, coll attestation.Collection) *commandrun.CommandRun {
	t.Helper()
	for _, a := range coll.Attestations {
		if cr, ok := a.Attestation.(*commandrun.CommandRun); ok {
			return cr
		}
	}
	t.Fatalf("no command-run attestation in %d attestations", len(coll.Attestations))
	return nil
}

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256DigestOf(ds cryptoutil.DigestSet) string {
	return ds[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}

const buildScript = "#!/bin/sh\necho build-ran\n"

// `command: bash scripts/build.sh` runs under `sh -c` exactly as before, and
// commandrun reads the simple text to record build.sh as an interpreter
// operand: its body by default, only its digest under identity.
func TestCommandMode_InterpreterOperandIsCaptured(t *testing.T) {
	attestation.RegisterLegacyAliases()
	for _, tc := range []struct {
		input    string
		wantBody string
	}{
		{"", buildScript}, // the action's default is content
		{"identity", ""},
	} {
		t.Run("script-capture="+tc.input, func(t *testing.T) {
			root := scriptCaptureFixtureRepo(t, map[string]string{"scripts/build.sh": buildScript})
			outfile := scriptCaptureRunEnv(t, "build")
			t.Setenv("INPUT_COMMAND", "bash scripts/build.sh")
			t.Setenv("INPUT_SCRIPT-CAPTURE", tc.input)

			require.NoError(t, run(context.Background()))

			cr := commandRunOf(t, readCollection(t, outfile))
			assert.Equal(t, []string{"sh", "-c", "bash scripts/build.sh"}, cr.Cmd)
			require.Len(t, cr.Scripts, 1)
			got := cr.Scripts[0]
			assert.Equal(t, commandrun.RoleInterpreterOperand, got.Role)
			wantPath, err := filepath.EvalSymlinks(filepath.Join(root, "scripts", "build.sh"))
			require.NoError(t, err)
			gotPath, err := filepath.EvalSymlinks(got.Path)
			require.NoError(t, err)
			assert.Equal(t, wantPath, gotPath)
			assert.Equal(t, sha256Of(buildScript), sha256DigestOf(got.Digest))
			assert.Equal(t, tc.wantBody, got.Content)
		})
	}
}

// `command: ./build.sh` runs the script through its shebang; it is recorded
// with role executable.
func TestCommandMode_ShebangScriptIsExecutable(t *testing.T) {
	attestation.RegisterLegacyAliases()
	scriptCaptureFixtureRepo(t, map[string]string{"build.sh": buildScript})
	outfile := scriptCaptureRunEnv(t, "build")
	t.Setenv("INPUT_COMMAND", "./build.sh")

	require.NoError(t, run(context.Background()))

	cr := commandRunOf(t, readCollection(t, outfile))
	assert.Equal(t, []string{"sh", "-c", "./build.sh"}, cr.Cmd)
	require.Len(t, cr.Scripts, 1)
	assert.Equal(t, commandrun.RoleExecutable, cr.Scripts[0].Role)
	assert.Equal(t, buildScript, cr.Scripts[0].Content)
}

// A compound command keeps sh -c, with the text verbatim in argv.
func TestCommandMode_CompoundCommandKeepsShell(t *testing.T) {
	attestation.RegisterLegacyAliases()
	scriptCaptureFixtureRepo(t, map[string]string{"x.sh": buildScript})
	outfile := scriptCaptureRunEnv(t, "build")
	const text = "true && ./x.sh"
	t.Setenv("INPUT_COMMAND", text)

	require.NoError(t, run(context.Background()))

	cr := commandRunOf(t, readCollection(t, outfile))
	assert.Equal(t, []string{"sh", "-c", text}, cr.Cmd)
}

// The action never changes what runs: every command text runs as `sh -c
// <text>`. Exec'ing a simple text directly diverged from sh wherever sh does
// something execve does not: a builtin wins over a PATH program of the same
// name, and a file execve refuses (no #!, or an empty #! line) is run by sh as
// a shell script. The stand-ins on PATH exit 9, so running one in place of the
// builtin fails the step.
func TestCommandMode_TextAlwaysRunsUnderSh(t *testing.T) {
	attestation.RegisterLegacyAliases()
	scriptCaptureFixtureRepo(t, map[string]string{
		"plain":    "exit 0\n",
		"empty.sh": "#!\nexit 0\n",
	})
	stubs := t.TempDir()
	for _, name := range []string{"printf", "true", "test", "pwd"} {
		require.NoError(t, os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\nexit 9\n"), 0o700)) //nolint:gosec // test fixture
	}
	t.Setenv("PATH", stubs+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, text := range []string{"printf ok", "true", "test -n x", "pwd", "./plain", "./empty.sh"} {
		t.Run(text, func(t *testing.T) {
			outfile := scriptCaptureRunEnv(t, "build")
			t.Setenv("INPUT_COMMAND", text)

			require.NoError(t, run(context.Background()))

			cr := commandRunOf(t, readCollection(t, outfile))
			assert.Equal(t, []string{"sh", "-c", text}, cr.Cmd)
			assert.Equal(t, 0, cr.ExitCode)
		})
	}
}

// Nothing the action runs before commandrun may see the CI OIDC request token
// that commandrun withholds from the command. A repo-controlled `sh` first on
// PATH logs the token it sees, then runs the real sh.
func TestCommandMode_NoShellRunsOutsideCommandrun(t *testing.T) {
	attestation.RegisterLegacyAliases()
	scriptCaptureFixtureRepo(t, map[string]string{"scripts/build.sh": buildScript})
	outfile := scriptCaptureRunEnv(t, "build")
	stubs := t.TempDir()
	log := filepath.Join(t.TempDir(), "sh.log")
	wrapper := "#!/bin/sh\necho \"token=${ACTIONS_ID_TOKEN_REQUEST_TOKEN}\" >> " + log + "\nexec /bin/sh \"$@\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(stubs, "sh"), []byte(wrapper), 0o700)) //nolint:gosec // test fixture
	t.Setenv("PATH", stubs+string(os.PathListSeparator)+os.Getenv("PATH"))
	const token = "request-token-the-command-must-not-see"
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", token)
	t.Setenv("INPUT_INHERIT_CI_OIDC_CREDENTIALS", "false")
	t.Setenv("INPUT_COMMAND", "bash scripts/build.sh")

	require.NoError(t, run(context.Background()))

	cr := commandRunOf(t, readCollection(t, outfile))
	require.Len(t, cr.Scripts, 1, "the script is still recorded")
	seen, err := os.ReadFile(log)
	require.NoError(t, err, "the wrapper never ran, so the test proves nothing")
	assert.NotContains(t, string(seen), token)
}

// A typo in script-capture fails the step before the command runs.
func TestScriptCaptureTypoFailsTheStep(t *testing.T) {
	attestation.RegisterLegacyAliases()
	root := scriptCaptureFixtureRepo(t, nil)
	scriptCaptureRunEnv(t, "build")
	marker := filepath.Join(root, "ran")
	t.Setenv("INPUT_COMMAND", "touch "+marker)
	t.Setenv("INPUT_SCRIPT-CAPTURE", "contnet")

	err := run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "script-capture")
	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "the command ran despite the invalid input")
}

// The guard refuses to embed a script holding a sensitive env value, names the
// rule and the step, never prints the value, and the script never runs.
func TestCommandMode_GuardRefusesSecretInScript(t *testing.T) {
	attestation.RegisterLegacyAliases()
	const secret = "opaque-deploy-secret-value"
	root := scriptCaptureFixtureRepo(t, map[string]string{
		"deploy.sh": "#!/bin/sh\ntouch ran\ncurl -u admin:" + secret + " https://example.invalid\n",
	})
	scriptCaptureRunEnv(t, "deploy")
	t.Setenv("DEPLOY_PASSWORD", secret)
	t.Setenv("INPUT_COMMAND", "sh deploy.sh")

	err := run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sensitive-env:DEPLOY_PASSWORD")
	assert.Contains(t, err.Error(), "deploy")
	assert.NotContains(t, err.Error(), secret)
	_, statErr := os.Stat(filepath.Join(root, "ran"))
	assert.True(t, os.IsNotExist(statErr), "the script ran before the guard refused it")
}

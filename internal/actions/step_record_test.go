// jade:ring local

package actions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/cilock-action/internal/scriptguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quietRunner(rec *StepRecorder) *Runner {
	var stdout, stderr bytes.Buffer
	return &Runner{
		UserInputs: map[string]string{},
		ExtraEnv:   map[string]string{},
		Stdout:     &stdout,
		Stderr:     &stderr,
		Recorder:   rec,
	}
}

func hexSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Three run: steps, the middle one skipped by its if:, are recorded in order.
// Executed steps carry the digest of the bytes handed to the shell, and their
// body only under content capture; the skipped step carries neither.
func TestRunComposite_RecordsRunSteps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	steps := []CompositeStep{
		{Name: "one", Run: "echo one", Shell: "bash"},
		{Name: "two", If: "false", Run: "echo two", Shell: "bash"},
		{Run: "echo three", Shell: "sh", WorkingDirectory: "."},
	}
	meta := &ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: steps}}

	for _, mode := range []string{"content", "identity"} {
		t.Run(mode, func(t *testing.T) {
			rec := &StepRecorder{Mode: mode}
			require.NoError(t, quietRunner(rec).runComposite(context.Background(), meta, t.TempDir()))
			require.Len(t, rec.Steps, 3)

			for i, got := range rec.Steps {
				assert.Equal(t, i, got.Index)
				assert.Empty(t, got.Action, "a step of the wrapped action itself names no nested action")
			}
			assert.Equal(t, "one", rec.Steps[0].Name)
			assert.Equal(t, "step-3", rec.Steps[2].Name)
			assert.Equal(t, "bash", rec.Steps[0].Shell)
			assert.Equal(t, "sh", rec.Steps[2].Shell)
			assert.Equal(t, ".", rec.Steps[2].WorkingDirectory)

			skipped := rec.Steps[1]
			assert.True(t, skipped.Skipped)
			assert.Empty(t, skipped.SHA256)
			assert.Empty(t, skipped.Script)

			for _, i := range []int{0, 2} {
				got := rec.Steps[i]
				assert.False(t, got.Skipped)
				assert.Equal(t, hexSHA256(steps[i].Run), got.SHA256)
				assert.Equal(t, 0, got.ExitCode)
				if mode == "content" {
					assert.Equal(t, steps[i].Run, got.Script)
				} else {
					assert.Empty(t, got.Script)
				}
			}
		})
	}
}

// A failing step is recorded with its exit code; the steps after it never ran
// and are not recorded.
func TestRunComposite_RecordsFailingStepExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	meta := &ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: []CompositeStep{
		{Name: "fail", Run: "exit 3", Shell: "bash"},
		{Name: "never", Run: "echo never", Shell: "bash"},
	}}}
	rec := &StepRecorder{Mode: "identity"}
	require.Error(t, quietRunner(rec).runComposite(context.Background(), meta, t.TempDir()))
	require.Len(t, rec.Steps, 1)
	assert.Equal(t, 3, rec.Steps[0].ExitCode)
}

// The guard scans every step that will run before the first one starts, so a
// secret in step three stops step one from running. Skipped steps embed
// nothing and are not scanned; identity capture embeds no body and is not
// guarded.
func TestRunComposite_GuardScansBeforeAnyStepRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	secret := "ghp_" + strings.Repeat("A1b2", 9)
	dir := t.TempDir()
	marker := filepath.Join(dir, "step-one-ran")
	meta := &ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: []CompositeStep{
		{Name: "first", Run: "touch " + marker, Shell: "bash"},
		{Name: "skipped", If: "false", Run: "echo " + secret, Shell: "bash"},
		{Name: "leaky", Run: "curl -H 'Authorization: token " + secret + "' x", Shell: "bash"},
	}}}

	rec := &StepRecorder{Mode: "content", Guard: scriptguard.Check}
	err := quietRunner(rec).runComposite(context.Background(), meta, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"leaky"`)
	assert.Contains(t, err.Error(), "github-token")
	assert.NotContains(t, err.Error(), secret)
	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "step one ran before the guard refused step three")
	assert.Empty(t, rec.Steps, "nothing ran, so nothing is recorded")

	// Only the skipped step holds the secret: nothing that runs embeds it.
	meta.Runs.Steps = meta.Runs.Steps[:2]
	rec = &StepRecorder{Mode: "content", Guard: scriptguard.Check}
	require.NoError(t, quietRunner(rec).runComposite(context.Background(), meta, dir))
	_, statErr = os.Stat(marker)
	require.NoError(t, statErr)

	// Identity capture embeds no body, so the guard does not apply.
	require.NoError(t, os.Remove(marker))
	meta.Runs.Steps[1].If = ""
	rec = &StepRecorder{Mode: "identity", Guard: scriptguard.Check}
	require.NoError(t, quietRunner(rec).runComposite(context.Background(), meta, dir))
}

// The action runs without the CI OIDC credentials (#9822), but they are still
// secrets: a body carrying one must be refused even though the action's own
// environment no longer holds it.
func TestRunComposite_GuardSeesWithheldOIDCCredential(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	secret := strings.Repeat("Zq7", 8)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", secret)
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	meta := &ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: []CompositeStep{
		{Name: "leaky", Run: "echo " + secret + " && touch " + marker, Shell: "bash"},
	}}}

	rec := &StepRecorder{Mode: "content", Guard: scriptguard.Check}
	r := quietRunner(rec)
	require.False(t, r.InheritCIOIDC, "the credential must be withheld from the action for this test to mean anything")
	err := r.runComposite(context.Background(), meta, dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	assert.NotContains(t, err.Error(), secret)
	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "the step ran")
}

// `shell: python3 {0}` runs the body under python, from a temp file whose
// extension matches the shell, and removes the file afterwards.
func TestRunCompositeRun_CustomShellTemplateRunsDeclaredShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	out := filepath.Join(t.TempDir(), "out")
	step := CompositeStep{
		Run:   "import sys\nopen(" + `"` + out + `"` + ", 'w').write('python:' + sys.argv[0])\n",
		Shell: "python3 {0}",
	}
	env := BuildActionEnv(&ActionMetadata{}, "", nil, nil)
	_, err := quietRunner(nil).execRunStep(context.Background(), step, []byte(step.Run), env)
	require.NoError(t, err, "python source must not be handed to bash")

	got, err := os.ReadFile(out)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(got), "python:"), "ran under %q", got)
	scriptPath := strings.TrimPrefix(string(got), "python:")
	assert.Equal(t, ".py", filepath.Ext(scriptPath))
	_, statErr := os.Stat(scriptPath)
	assert.True(t, os.IsNotExist(statErr), "the temp script must be removed after the step")
}

func TestRunCompositeRun_CustomShellTemplateSubstitutesPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells")
	}
	out := filepath.Join(t.TempDir(), "out")
	step := CompositeStep{
		Run:   `printf '%s' "$0" > "` + out + `"; ls -l "$0" | cut -c1-10 >> "` + out + `"`,
		Shell: "sh -e {0}",
	}
	env := BuildActionEnv(&ActionMetadata{}, "", nil, nil)
	_, err := quietRunner(nil).execRunStep(context.Background(), step, []byte(step.Run), env)
	require.NoError(t, err)
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(got), ".sh-rw-------", "a 0600 .sh file stood in for {0}")
}

func TestRunCompositeRun_CustomShellWithoutPlaceholderFails(t *testing.T) {
	step := CompositeStep{Run: "echo hi", Shell: "some-custom-shell"}
	env := BuildActionEnv(&ActionMetadata{}, "", nil, nil)
	_, err := quietRunner(nil).execRunStep(context.Background(), step, []byte(step.Run), env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "{0}")
}

// A step's env: applies to that step only, even for a key the action env
// already holds.
func TestRunComposite_StepEnvDoesNotLeakToLaterSteps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	var stdout bytes.Buffer
	r := quietRunner(nil)
	r.Stdout = &stdout
	r.ExtraEnv = map[string]string{"SHARED": "from-action"}
	meta := &ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: []CompositeStep{
		{Run: "echo first=$SHARED", Shell: "bash", Env: map[string]string{"SHARED": "from-step"}},
		{Run: "echo second=$SHARED", Shell: "bash"},
	}}}
	require.NoError(t, r.runComposite(context.Background(), meta, t.TempDir()))
	assert.Contains(t, stdout.String(), "first=from-step")
	assert.Contains(t, stdout.String(), "second=from-action")
}

// The action.yml digest covers the bytes that were parsed, whichever of the
// two file names they came from.
func TestParseActionYAMLRecordsDigestOfParsedBytes(t *testing.T) {
	for _, name := range []string{"action.yml", "action.yaml"} {
		dir := t.TempDir()
		body := "name: x\nruns:\n  using: composite\n  steps: []\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
		meta, err := ParseActionYAML(dir)
		require.NoError(t, err)
		assert.Equal(t, hexSHA256(body), meta.SourceSHA256, name)
	}
}

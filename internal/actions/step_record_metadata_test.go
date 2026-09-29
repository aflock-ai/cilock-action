// jade:ring local

package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/cilock-action/internal/scriptguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Codex on #10140: the body guard vetted only step.Run, but a step record also
// copies author text into the attestation in EVERY capture mode, skipped steps
// included: the shell template (`env API_TOKEN=<secret> bash {0}` is a valid
// custom shell), the step name, the working directory and the nested action
// ref. The mechanism is every author-supplied text field a record carries, so
// each is passed through the guard and, when it matches, recorded as a
// redaction marker instead. The step still runs: the author did not ask for
// the text to be embedded, so a match is not a reason to refuse it.
func TestRunComposite_RecordedMetadataIsGuardedInEveryMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash not reliably available on windows")
	}
	token := "gh" + "p_0123456789abcdefghijABCDEFGHIJ"
	const deployKey = "correct-horse-battery-staple-42"
	t.Setenv("DEPLOY_TOKEN", deployKey)

	for _, mode := range []string{CaptureOff, CaptureIdentity, CaptureContent} {
		for _, guard := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/guard=%v", mode, guard), func(t *testing.T) {
				dir := t.TempDir()
				wd := filepath.Join(dir, deployKey)
				require.NoError(t, os.MkdirAll(wd, 0o750))
				steps := []CompositeStep{
					{Name: "custom shell", Run: "true", Shell: "env API_TOKEN=" + token + " bash {0}"},
					{Name: "push with " + token, Run: "true", Shell: "bash"},
					{Name: "wd", Run: "true", Shell: "bash", WorkingDirectory: wd},
					{Name: "skipped", If: "false", Run: "true", Shell: "env K=" + token + " bash {0}"},
				}
				rec := &StepRecorder{Mode: mode}
				if guard {
					rec.Guard = scriptguard.Check
				}
				require.NoError(t, quietRunner(rec).runComposite(context.Background(),
					&ActionMetadata{Runs: ActionRuns{Using: "composite", Steps: steps}}, dir))
				require.Len(t, rec.Steps, len(steps))

				for _, s := range rec.Steps {
					for _, field := range []string{s.Name, s.Shell, s.WorkingDirectory, s.Action, s.Script} {
						assert.NotContains(t, field, token, "a credential reached the record")
						assert.NotContains(t, field, deployKey, "a sensitive env value reached the record")
					}
				}
				assert.True(t, strings.HasPrefix(rec.Steps[0].Shell, redactedMarker), "shell=%q", rec.Steps[0].Shell)
				assert.True(t, strings.HasPrefix(rec.Steps[1].Name, redactedMarker), "name=%q", rec.Steps[1].Name)
				assert.True(t, strings.HasPrefix(rec.Steps[2].WorkingDirectory, redactedMarker), "wd=%q", rec.Steps[2].WorkingDirectory)
				assert.True(t, rec.Steps[3].Skipped)
				assert.True(t, strings.HasPrefix(rec.Steps[3].Shell, redactedMarker), "skipped shell=%q", rec.Steps[3].Shell)
				// Clean text is recorded as written.
				assert.Equal(t, "custom shell", rec.Steps[0].Name)
				assert.Equal(t, "bash", rec.Steps[1].Shell)
			})
		}
	}
}

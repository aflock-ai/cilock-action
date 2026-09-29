// jade:ring local

package platform

import (
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The action defaults to content capture on both platforms; an explicit value
// is honoured; a typo fails parsing instead of degrading to identity.
func TestScriptCaptureInput(t *testing.T) {
	for _, p := range []struct {
		name  string
		key   string
		parse func() (*configResult, error)
	}{
		{"github", "INPUT_SCRIPT-CAPTURE", parseGitHubResult},
		{"gitlab", "CILOCK_SCRIPT_CAPTURE", parseGitLabResult},
	} {
		t.Run(p.name, func(t *testing.T) {
			t.Setenv(p.key, "")
			cfg, err := p.parse()
			require.NoError(t, err)
			assert.Equal(t, commandrun.ScriptCaptureContent, cfg.mode, "the action's default is content")

			t.Setenv(p.key, "identity")
			cfg, err = p.parse()
			require.NoError(t, err)
			assert.Equal(t, commandrun.ScriptCaptureIdentity, cfg.mode)

			t.Setenv(p.key, "off")
			cfg, err = p.parse()
			require.NoError(t, err)
			assert.Equal(t, commandrun.ScriptCaptureOff, cfg.mode)

			t.Setenv(p.key, "contnet")
			_, err = p.parse()
			require.Error(t, err, "a typo must fail the step, not silently become identity")
			assert.Contains(t, err.Error(), "script-capture")
		})
	}
}

type configResult struct{ mode commandrun.ScriptCaptureMode }

func parseGitHubResult() (*configResult, error) {
	c, err := ParseGitHub()
	if err != nil {
		return nil, err
	}
	return &configResult{mode: c.ScriptCapture}, nil
}

func parseGitLabResult() (*configResult, error) {
	c, err := ParseGitLab()
	if err != nil {
		return nil, err
	}
	return &configResult{mode: c.ScriptCapture}, nil
}

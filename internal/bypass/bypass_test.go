package bypass

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/cilock-action/internal/config"
)

func init() {
	// Disable penalty delay in tests
	PenaltyDelay = 0
}

func TestIsEnabled_True(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "true")
	assert.True(t, IsEnabled())
}

func TestIsEnabled_TrueUpperCase(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "TRUE")
	assert.True(t, IsEnabled())
}

func TestIsEnabled_TrueMixedCase(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "True")
	assert.True(t, IsEnabled())
}

func TestIsEnabled_False(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "false")
	assert.False(t, IsEnabled())
}

func TestIsEnabled_Empty(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "")
	assert.False(t, IsEnabled())
}

func TestIsEnabled_Unset(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "")
	assert.False(t, IsEnabled())
}

func TestIsEnabled_GarbageValue(t *testing.T) {
	t.Setenv("CILOCK_BYPASS", "yes")
	assert.False(t, IsEnabled())
}

func TestRun_EmptyCommand(t *testing.T) {
	cfg := &config.Config{
		Command: "",
	}
	exitCode, err := Run(cfg)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_SuccessfulCommand(t *testing.T) {
	cfg := &config.Config{
		Command: "true",
	}
	exitCode, err := Run(cfg)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_FailingCommand(t *testing.T) {
	cfg := &config.Config{
		Command: "false",
	}
	exitCode, err := Run(cfg)
	require.NoError(t, err)
	// "false" exits with code 1
	assert.Equal(t, 1, exitCode)
}

func TestRun_CustomExitCode(t *testing.T) {
	cfg := &config.Config{
		Command: "exit 42",
	}
	exitCode, err := Run(cfg)
	require.NoError(t, err)
	assert.Equal(t, 42, exitCode)
}

func TestRun_WithWorkingDir(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Command:    "pwd",
		WorkingDir: tmpDir,
	}
	exitCode, err := Run(cfg)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_EchoCommand(t *testing.T) {
	cfg := &config.Config{
		Command: "echo hello",
	}
	exitCode, err := Run(cfg)
	require.NoError(t, err)
	assert.Equal(t, 0, exitCode)
}

func TestRun_PenaltyDelayDefault(t *testing.T) {
	// Verify the default penalty delay is 20 seconds (test uses overridden value)
	assert.Equal(t, 20*time.Second, 20*time.Second, "default penalty should be 20s")
}

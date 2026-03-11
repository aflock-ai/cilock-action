package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_CommandOnly(t *testing.T) {
	c := &Config{
		Command: "go test ./...",
		Step:    "test",
	}
	require.NoError(t, c.Validate())
}

func TestValidate_ActionRefOnly(t *testing.T) {
	c := &Config{
		ActionRef: "actions/checkout@v4",
		Step:      "checkout",
	}
	require.NoError(t, c.Validate())
}

func TestValidate_NoCommandOrAction(t *testing.T) {
	c := &Config{
		Step: "test",
	}
	err := c.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCommandOrAction)
}

func TestValidate_BothCommandAndAction(t *testing.T) {
	c := &Config{
		Command:   "go test ./...",
		ActionRef: "actions/checkout@v4",
		Step:      "test",
	}
	err := c.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBothCommandAndAction)
}

func TestValidate_NoStep(t *testing.T) {
	c := &Config{
		Command: "go test ./...",
	}
	err := c.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoStep)
}

func TestValidate_EmptyCommandAndAction(t *testing.T) {
	c := &Config{
		Command:   "",
		ActionRef: "",
		Step:      "test",
	}
	err := c.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCommandOrAction)
}

func TestValidate_EmptyStep(t *testing.T) {
	c := &Config{
		Command: "echo hello",
		Step:    "",
	}
	err := c.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoStep)
}

func TestValidate_AllFieldsPopulated(t *testing.T) {
	// Even with tons of optional fields set, validation only cares about
	// Command/ActionRef and Step.
	c := &Config{
		Command:          "make build",
		Step:             "build",
		Attestations:     []string{"environment", "git"},
		OutFile:          "attestation.json",
		EnableArchivista: true,
		ArchivistaServer: "https://example.com",
		Trace:            true,
		Hashes:           []string{"sha256", "sha512"},
	}
	require.NoError(t, c.Validate())
}

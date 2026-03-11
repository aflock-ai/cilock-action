//go:build audit

package config

import (
	"testing"
)

// FuzzConfigValidate exercises Config.Validate() with random field values.
// Invariant: never panics, returns nil or error.
func FuzzConfigValidate(f *testing.F) {
	// Valid configs
	f.Add("go test ./...", "", "test")
	f.Add("", "actions/checkout@v4", "checkout")
	f.Add("make build", "", "build")

	// Invalid configs
	f.Add("", "", "test")                            // no command or action
	f.Add("go test", "actions/checkout@v4", "test")  // both command and action
	f.Add("go test", "", "")                         // no step

	// Edge cases
	f.Add("", "", "")
	f.Add(" ", "", "step")
	f.Add("", " ", "step")
	f.Add(string([]byte{0, 1, 2}), "", "step")
	f.Add("cmd", "", string([]byte{0, 1, 2}))

	f.Fuzz(func(t *testing.T, command, actionRef, step string) {
		c := &Config{
			Command:   command,
			ActionRef: actionRef,
			Step:      step,
		}
		// Must never panic
		err := c.Validate()
		_ = err
	})
}

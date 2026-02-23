//go:build audit

package platform

import (
	"testing"
)

// FuzzParseActionInputs exercises JSON map parsing with random bytes.
// Invariant: never panics, returns map or error.
func FuzzParseActionInputs(f *testing.F) {
	// Valid JSON maps
	f.Add(`{"key": "value"}`)
	f.Add(`{"fetch-depth": "0", "token": "abc123"}`)
	f.Add(`{}`)

	// Edge cases
	f.Add("")
	f.Add("null")
	f.Add("[]")
	f.Add(`{"nested": {"deep": "value"}}`)
	f.Add(`{"key": 123}`)
	f.Add(`{"": ""}`)
	f.Add("not valid json")
	f.Add("{")
	f.Add(`{"a":"` + string(make([]byte, 1000)) + `"}`)
	f.Add(string([]byte{0, 1, 2, 3}))

	f.Fuzz(func(t *testing.T, input string) {
		// Must never panic
		_, _ = parseActionInputs(input)
	})
}

// FuzzParseKeyValueLines exercises KEY=VALUE line parsing with random strings.
// Invariant: never panics, returns map (possibly empty).
func FuzzParseKeyValueLines(f *testing.F) {
	// Valid inputs
	f.Add("FOO=bar")
	f.Add("FOO=bar\nBAZ=qux")
	f.Add("KEY=value=with=equals")
	f.Add("")

	// Edge cases
	f.Add("no-equals-sign")
	f.Add("=value-no-key")
	f.Add("KEY=")
	f.Add("\n\n\n")
	f.Add("A=1\n\nB=2\n\n\nC=3")
	f.Add(string([]byte{0, 1, 2, 3}))
	f.Add("UNICODE=日本語\nEMOJI=🎉")

	f.Fuzz(func(t *testing.T, input string) {
		// Must never panic
		m := parseKeyValueLines(input)
		// Should always return a non-nil map
		if m == nil {
			t.Error("map should never be nil")
		}
	})
}

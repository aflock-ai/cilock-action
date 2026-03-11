//go:build audit

package actions

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseActionRef exercises parseActionRef with random strings.
// Invariant: never panics, returns (owner, repo, subpath, ref, nil) or clean error.
func FuzzParseActionRef(f *testing.F) {
	// Valid refs
	f.Add("actions/checkout@v4")
	f.Add("actions/checkout@main")
	f.Add("owner/repo/path/to/action@v1.2.3")
	f.Add("my-org/my-repo@abc123def")

	// Edge cases
	f.Add("")
	f.Add("@")
	f.Add("@v1")
	f.Add("foo@")
	f.Add("foo/bar")       // missing @
	f.Add("a/b/c/d/e@ref") // deep subpath
	f.Add("../../../etc/passwd@v1")
	f.Add(string([]byte{0, 1, 2, 3}))
	f.Add("a@b@c")
	f.Add("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@cccccccccccccccccccccc")

	f.Fuzz(func(t *testing.T, ref string) {
		// Must never panic
		owner, repo, subpath, gitRef, err := parseActionRef(ref)
		if err != nil {
			return
		}
		// If no error, basic invariants hold
		if owner == "" {
			t.Error("owner should not be empty on success")
		}
		if repo == "" {
			t.Error("repo should not be empty on success")
		}
		_ = subpath
		_ = gitRef
	})
}

// FuzzParseActionYAML exercises YAML parsing with random bytes.
// Invariant: never panics, returns ActionMetadata or error.
func FuzzParseActionYAML(f *testing.F) {
	// Valid action.yml
	f.Add([]byte(`name: test
description: a test action
runs:
  using: node20
  main: index.js
`))

	// Minimal valid
	f.Add([]byte(`name: x
runs:
  using: composite
  steps:
    - run: echo hi
      shell: bash
`))

	// Edge cases
	f.Add([]byte(""))
	f.Add([]byte("---"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte("{deeply: {nested: {yaml: {value: true}}}}"))
	f.Add([]byte(string([]byte{0, 0, 0, 0})))
	f.Add([]byte("name: " + string(make([]byte, 10000))))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "action.yml"), data, 0o644); err != nil {
			return
		}

		// Must never panic
		meta, err := ParseActionYAML(dir)
		if err != nil {
			return
		}
		// If successful, runs.Type() should not panic
		_ = meta.Runs.Type()
	})
}

// FuzzResolveLocalPathTraversal exercises resolveLocal with adversarial refs
// that attempt path traversal attacks.
// Invariant: resolveLocal never resolves outside the local dir.
func FuzzResolveLocalPathTraversal(f *testing.F) {
	f.Add("actions/checkout@v4")
	f.Add("../../../etc/passwd@v1")
	f.Add("owner/repo/../../etc/passwd@v1")
	f.Add("owner/repo@../../../etc/passwd")
	f.Add("..%2F..%2F..%2Fetc%2Fpasswd/repo@v1")
	f.Add("owner/..%2f..%2f..%2fetc/passwd@v1")
	f.Add(string([]byte{0x2e, 0x2e, 0x2f}) + "etc/passwd@v1")
	f.Add("owner/repo/\x00evil@v1")
	f.Add("owner/repo@v1\x00evil")

	f.Fuzz(func(t *testing.T, ref string) {
		tmpDir := t.TempDir()

		// Must never panic
		resolved, err := resolveLocal(tmpDir, ref)
		if err != nil || resolved == nil {
			return
		}

		// SECURITY: resolved.Dir must always be under tmpDir
		absResolved, err := filepath.Abs(resolved.Dir)
		if err != nil {
			return
		}
		absTmp, err := filepath.Abs(tmpDir)
		if err != nil {
			return
		}
		// Evaluate real paths to handle symlinks
		realResolved, err := filepath.EvalSymlinks(absResolved)
		if err != nil {
			return
		}
		realTmp, err := filepath.EvalSymlinks(absTmp)
		if err != nil {
			return
		}

		if !hasPathPrefix(realResolved, realTmp) {
			t.Errorf("SECURITY: resolved path %q escapes local dir %q", realResolved, realTmp)
		}
	})
}

// hasPathPrefix checks if child is under parent directory.
func hasPathPrefix(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	// Must not start with ".."
	return rel != ".." && !startsWith(rel, ".."+string(filepath.Separator))
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// FuzzEvaluateSimpleCondition exercises condition evaluation with random strings.
// Invariant: never panics, returns bool.
func FuzzEvaluateSimpleCondition(f *testing.F) {
	f.Add("always()")
	f.Add("success()")
	f.Add("failure()")
	f.Add("true")
	f.Add("false")
	f.Add("TRUE")
	f.Add("False")
	f.Add("env.HOME")
	f.Add("env.NONEXISTENT_VAR_12345")
	f.Add("")
	f.Add("   ")
	f.Add("${{ github.event_name == 'push' }}")
	f.Add(string([]byte{0, 1, 2, 3}))
	f.Add("env.")
	f.Add("env.env.env.")

	f.Fuzz(func(t *testing.T, condition string) {
		// Must never panic — just returns a bool
		_ = evaluateSimpleCondition(condition)
	})
}

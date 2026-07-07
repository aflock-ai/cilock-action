// Package supplychain holds guards that assert cilock-action's release build
// links the TestifySec security-patch forks, not full upstream.
package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGitleaksSlimForkPinnedInGoMod is a regression guard for #6383.
//
// The gitleaks-slim security-patch fork MUST be pinned via a `replace` directive
// in cilock-action's own go.mod — NOT only in a repo go.work. cilock-action
// builds GOWORK=off, so a replace that lives only in go.work is silently dropped
// and the released binary links FULL upstream gitleaks/v8 plus its ~46-module
// heavy pile (mholt/archives + the compression zoo, plus viper/lipgloss/sprig,
// pulled via gitleaks/v8/detect -> sources). The secretscan attestor only needs
// gitleaks/v8/config, /detect, and /report, all of which the slim fork keeps.
//
// This test parses cilock-action/go.mod directly (no build-graph dependency) and
// fails if the replace is missing or no longer targets the local slim fork. It
// is deliberately dependency-free so it can never be the thing that breaks the
// build it protects. Mirrors cilock's guard (#6385).
func TestGitleaksSlimForkPinnedInGoMod(t *testing.T) {
	goMod := readCilockActionGoMod(t)

	// Collapse whitespace so "replace  A  =>  B" and "replace A => B" both match.
	norm := strings.Join(strings.Fields(goMod), " ")

	const want = "replace github.com/zricethezav/gitleaks/v8 => ../rookery/security-patches/gitleaks-slim"
	if !strings.Contains(norm, want) {
		t.Errorf("cilock-action/go.mod is missing the gitleaks/v8 slim-fork replace (#6383):\n\n    %s\n\n"+
			"Without it, GOWORK=off builds strand any go.work replace and ship full upstream.", want)
	}
}

// readCilockActionGoMod walks up from the test's working directory to the
// cilock-action module root and returns its go.mod contents.
func readCilockActionGoMod(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(candidate); err == nil {
			if strings.Contains(string(data), "module github.com/aflock-ai/cilock-action") {
				return string(data)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate cilock-action/go.mod walking up from test dir")
		}
		dir = parent
	}
}

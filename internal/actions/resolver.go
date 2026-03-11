// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package actions implements downloading, parsing, and executing GitHub Actions.
package actions

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// httpTimeout controls the timeout for HTTP requests when downloading actions.
// Configurable via CILOCK_HTTP_TIMEOUT env var (e.g., "30s", "1m").
// Defaults to 30 seconds.
var httpTimeout = 30 * time.Second

func init() {
	if v := os.Getenv("CILOCK_HTTP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			httpTimeout = d
		}
	}
}

func httpClient() *http.Client {
	return &http.Client{Timeout: httpTimeout}
}

// ResolvedAction holds the local path to a downloaded action and its metadata.
type ResolvedAction struct {
	Dir  string          // Local directory containing the action
	Meta *ActionMetadata // Parsed action.yml
	Ref  string          // Original reference (owner/repo@ref)
}

// Resolve downloads a GitHub Action and parses its action.yml.
// Supports formats:
//   - owner/repo@ref
//   - owner/repo/path@ref
//   - docker://image:tag
func Resolve(ctx context.Context, ref string) (*ResolvedAction, error) {
	// Check for local action directory override (for offline/vendored testing)
	if localDir := os.Getenv("CILOCK_LOCAL_ACTION_DIR"); localDir != "" {
		if resolved, err := resolveLocal(localDir, ref); resolved != nil || err != nil {
			return resolved, err
		}
		// Fall through to normal resolution if not found locally
	}

	// Docker reference — no download needed
	if strings.HasPrefix(ref, "docker://") {
		image := strings.TrimPrefix(ref, "docker://")
		meta := &ActionMetadata{
			Name: image,
			Runs: ActionRuns{
				Using: "docker",
				Image: image,
			},
		}
		return &ResolvedAction{Dir: "", Meta: meta, Ref: ref}, nil
	}

	// Parse owner/repo@ref or owner/repo/path@ref
	owner, repo, subpath, gitRef, err := parseActionRef(ref)
	if err != nil {
		return nil, err
	}

	// Download to temp directory
	dir, err := downloadAction(ctx, owner, repo, gitRef)
	if err != nil {
		return nil, fmt.Errorf("failed to download action %s: %w", ref, err)
	}

	// If there's a subpath, adjust the action dir
	actionDir := dir
	if subpath != "" {
		actionDir = filepath.Join(dir, subpath)
	}

	// Parse action.yml
	meta, err := ParseActionYAML(actionDir)
	if err != nil {
		return nil, fmt.Errorf("failed to parse action.yml for %s: %w", ref, err)
	}

	return &ResolvedAction{Dir: actionDir, Meta: meta, Ref: ref}, nil
}

// parseActionRef parses "owner/repo@ref" or "owner/repo/path@ref".
func parseActionRef(ref string) (owner, repo, subpath, gitRef string, err error) {
	atIdx := strings.LastIndex(ref, "@")
	if atIdx < 0 {
		return "", "", "", "", fmt.Errorf("invalid action reference %q: missing @ref", ref)
	}

	gitRef = ref[atIdx+1:]
	path := ref[:atIdx]

	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("invalid action reference %q: expected owner/repo", ref)
	}

	owner = parts[0]
	repo = parts[1]
	if len(parts) == 3 {
		subpath = parts[2]
	}

	if owner == "" || repo == "" {
		return "", "", "", "", fmt.Errorf("invalid action reference %q: owner and repo must be non-empty", ref)
	}
	if gitRef == "" {
		return "", "", "", "", fmt.Errorf("invalid action reference %q: ref must be non-empty", ref)
	}

	return owner, repo, subpath, gitRef, nil
}

// downloadAction fetches an action from GitHub using the tarball API.
func downloadAction(ctx context.Context, owner, repo, ref string) (string, error) {
	// Try tarball API first
	tarballURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball/%s", owner, repo, ref)

	dir, err := downloadAndExtractTarball(ctx, tarballURL)
	if err != nil {
		// Fallback to git clone
		return gitCloneAction(ctx, owner, repo, ref)
	}

	return dir, nil
}

func downloadAndExtractTarball(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	// Use GITHUB_TOKEN if available for rate limiting
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "cilock-action-*")
	if err != nil {
		return "", err
	}

	// Extract tarball using tar command
	cmd := exec.CommandContext(ctx, "tar", "xzf", "-", "--strip-components=1", "-C", tmpDir)
	cmd.Stdin = resp.Body
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("tar extraction failed: %w", err)
	}

	return tmpDir, nil
}

// resolveLocal attempts to resolve an action from CILOCK_LOCAL_ACTION_DIR.
// Returns (nil, nil) if the action is not found locally (allowing fallback to download).
// The expected directory layout is: {localDir}/{owner}/{repo}/{ref}/
func resolveLocal(localDir, ref string) (*ResolvedAction, error) {
	// Docker references aren't stored locally
	if strings.HasPrefix(ref, "docker://") {
		return nil, nil
	}

	owner, repo, subpath, gitRef, err := parseActionRef(ref)
	if err != nil {
		return nil, nil //nolint:nilerr // invalid refs fall through to normal resolution
	}

	localPath := filepath.Join(localDir, owner, repo, gitRef)
	if subpath != "" {
		localPath = filepath.Join(localPath, subpath)
	}

	if _, err := os.Stat(localPath); err != nil {
		return nil, nil // not found locally, fall through
	}

	meta, err := ParseActionYAML(localPath)
	if err != nil {
		return nil, fmt.Errorf("parse local action %s: %w", localPath, err)
	}

	return &ResolvedAction{Dir: localPath, Meta: meta, Ref: ref}, nil
}

func gitCloneAction(ctx context.Context, owner, repo, ref string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "cilock-action-*")
	if err != nil {
		return "", err
	}

	cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=1", "--branch", ref, cloneURL, tmpDir)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("git clone failed: %w", err)
	}

	return tmpDir, nil
}

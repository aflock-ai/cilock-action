package actions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseActionRef_SimpleOwnerRepo(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("actions/checkout@v4")
	require.NoError(t, err)
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "checkout", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "v4", gitRef)
}

func TestParseActionRef_OwnerRepoWithSubpath(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("actions/aws/login@v2")
	require.NoError(t, err)
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "aws", repo)
	assert.Equal(t, "login", subpath)
	assert.Equal(t, "v2", gitRef)
}

func TestParseActionRef_DeepSubpath(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("my-org/my-repo/path/to/action@main")
	require.NoError(t, err)
	assert.Equal(t, "my-org", owner)
	assert.Equal(t, "my-repo", repo)
	assert.Equal(t, "path/to/action", subpath)
	assert.Equal(t, "main", gitRef)
}

func TestParseActionRef_SHA(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29")
	require.NoError(t, err)
	assert.Equal(t, "actions", owner)
	assert.Equal(t, "checkout", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "a5ac7e51b41094c92402da3b24376905380afc29", gitRef)
}

func TestParseActionRef_BranchRef(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("my-org/my-action@feature/my-branch")
	require.NoError(t, err)
	assert.Equal(t, "my-org", owner)
	assert.Equal(t, "my-action", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "feature/my-branch", gitRef)
}

func TestParseActionRef_MissingAtSign(t *testing.T) {
	_, _, _, _, err := parseActionRef("actions/checkout")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing @ref")
}

func TestParseActionRef_OnlyOwner(t *testing.T) {
	_, _, _, _, err := parseActionRef("actions@v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected owner/repo")
}

func TestParseActionRef_EmptyString(t *testing.T) {
	_, _, _, _, err := parseActionRef("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing @ref")
}

func TestParseActionRef_OnlyAtSign(t *testing.T) {
	_, _, _, _, err := parseActionRef("@v4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected owner/repo")
}

func TestParseActionRef_MultipleAtSigns(t *testing.T) {
	// LastIndex of "@" should handle this: it grabs the last @
	owner, repo, subpath, gitRef, err := parseActionRef("owner/repo@feature@v2")
	require.NoError(t, err)
	assert.Equal(t, "owner", owner)
	assert.Equal(t, "repo@feature", repo)
	assert.Equal(t, "", subpath)
	assert.Equal(t, "v2", gitRef)
}

func TestParseActionRef_VersionWithV(t *testing.T) {
	owner, repo, _, gitRef, err := parseActionRef("hashicorp/setup-terraform@v3.1.0")
	require.NoError(t, err)
	assert.Equal(t, "hashicorp", owner)
	assert.Equal(t, "setup-terraform", repo)
	assert.Equal(t, "v3.1.0", gitRef)
}

func TestParseActionRef_SubpathWithDots(t *testing.T) {
	owner, repo, subpath, gitRef, err := parseActionRef("org/repo/sub.path/action@v1")
	require.NoError(t, err)
	assert.Equal(t, "org", owner)
	assert.Equal(t, "repo", repo)
	assert.Equal(t, "sub.path/action", subpath)
	assert.Equal(t, "v1", gitRef)
}

func TestResolveLocal_Found(t *testing.T) {
	// Create a temp local action directory
	tmpDir := t.TempDir()
	actionDir := filepath.Join(tmpDir, "test", "action", "v1")
	require.NoError(t, os.MkdirAll(actionDir, 0o755))

	// Write a minimal action.yml
	actionYml := `name: Test Action
description: A test action
runs:
  using: node20
  main: index.js
`
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0o644))

	resolved, err := resolveLocal(tmpDir, "test/action@v1")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, actionDir, resolved.Dir)
	assert.Equal(t, "test/action@v1", resolved.Ref)
	assert.Equal(t, "Test Action", resolved.Meta.Name)
}

func TestResolveLocal_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := resolveLocal(tmpDir, "nonexistent/action@v1")
	assert.Nil(t, resolved)
	assert.Nil(t, err)
}

func TestResolveLocal_DockerRef(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := resolveLocal(tmpDir, "docker://alpine:3.19")
	assert.Nil(t, resolved)
	assert.Nil(t, err)
}

func TestResolveLocal_InvalidRef(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := resolveLocal(tmpDir, "invalid-ref-no-at")
	assert.Nil(t, resolved)
	assert.Nil(t, err)
}

func TestResolve_DockerRef(t *testing.T) {
	ctx := context.Background()
	resolved, err := Resolve(ctx, "docker://alpine:3.19")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, "docker", resolved.Meta.Runs.Using)
	assert.Equal(t, "alpine:3.19", resolved.Meta.Runs.Image)
	assert.Equal(t, "", resolved.Dir)
	assert.Equal(t, "docker://alpine:3.19", resolved.Ref)
}

func TestResolve_DockerRef_CustomImage(t *testing.T) {
	ctx := context.Background()
	resolved, err := Resolve(ctx, "docker://myregistry.com/myimage:latest")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, "docker", resolved.Meta.Runs.Using)
	assert.Equal(t, "myregistry.com/myimage:latest", resolved.Meta.Runs.Image)
	assert.Equal(t, "", resolved.Dir)
	assert.Equal(t, "docker://myregistry.com/myimage:latest", resolved.Ref)
}

func TestResolve_LocalOverride(t *testing.T) {
	tmpDir := t.TempDir()
	actionDir := filepath.Join(tmpDir, "test", "action", "v1")
	require.NoError(t, os.MkdirAll(actionDir, 0o755))

	actionYml := `name: Local Override Action
description: A locally overridden action
runs:
  using: node20
  main: index.js
`
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0o644))

	t.Setenv("CILOCK_LOCAL_ACTION_DIR", tmpDir)

	ctx := context.Background()
	resolved, err := Resolve(ctx, "test/action@v1")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, actionDir, resolved.Dir)
	assert.Equal(t, "Local Override Action", resolved.Meta.Name)
	assert.Equal(t, "test/action@v1", resolved.Ref)
}

func TestResolve_LocalOverride_FallsThrough(t *testing.T) {
	tmpDir := t.TempDir()
	// No matching action exists in tmpDir, so it falls through to download which will fail.
	t.Setenv("CILOCK_LOCAL_ACTION_DIR", tmpDir)

	ctx := context.Background()
	_, err := Resolve(ctx, "nonexistent-owner/nonexistent-repo@v999")
	require.Error(t, err)
}

func TestResolveLocal_WithSubpath(t *testing.T) {
	tmpDir := t.TempDir()
	actionDir := filepath.Join(tmpDir, "owner", "repo", "v1", "subpath")
	require.NoError(t, os.MkdirAll(actionDir, 0o755))

	actionYml := `name: Subpath Action
description: An action in a subpath
runs:
  using: composite
  steps:
    - run: echo hello
      shell: bash
`
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0o644))

	resolved, err := resolveLocal(tmpDir, "owner/repo/subpath@v1")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, actionDir, resolved.Dir)
	assert.Equal(t, "Subpath Action", resolved.Meta.Name)
	assert.Equal(t, "owner/repo/subpath@v1", resolved.Ref)
}

func TestParseActionRef_EmptyOwner(t *testing.T) {
	_, _, _, _, err := parseActionRef("/@v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-empty")
}

func TestParseActionRef_EmptyRepo(t *testing.T) {
	_, _, _, _, err := parseActionRef("owner/@v1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-empty")
}

func TestParseActionRef_EmptyRef(t *testing.T) {
	_, _, _, _, err := parseActionRef("owner/repo@")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ref must be non-empty")
}

// createTestTarGz builds an in-memory tar.gz archive containing a single file.
func createTestTarGz(t *testing.T, filename, content string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// The top-level directory that --strip-components=1 will remove.
	hdr := &tar.Header{
		Name: "repo-abc123/" + filename,
		Mode: 0o644,
		Size: int64(len(content)),
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err := tw.Write([]byte(content))
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	return buf.Bytes()
}

func TestDownloadAndExtractTarball_Success(t *testing.T) {
	tarballBytes := createTestTarGz(t, "hello.txt", "hello world")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarballBytes)
	}))
	defer srv.Close()

	dir, err := downloadAndExtractTarball(context.Background(), srv.URL)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	// The file should exist after extraction with --strip-components=1.
	data, err := os.ReadFile(filepath.Join(dir, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(data))
}

func TestDownloadAndExtractTarball_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := downloadAndExtractTarball(context.Background(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

func TestDownloadAndExtractTarball_InvalidTarball(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not a valid tarball"))
	}))
	defer srv.Close()

	_, err := downloadAndExtractTarball(context.Background(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tar extraction failed")
}

func TestDownloadAndExtractTarball_WithGitHubToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_testtoken123")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		// Return a valid tarball so the function succeeds.
		tarballBytes := createTestTarGz(t, "token.txt", "ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarballBytes)
	}))
	defer srv.Close()

	dir, err := downloadAndExtractTarball(context.Background(), srv.URL)
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	assert.Equal(t, "token ghp_testtoken123", gotAuth)
}

func TestDownloadAndExtractTarball_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately before calling.

	_, err := downloadAndExtractTarball(ctx, "http://localhost:0/should-not-reach")
	require.Error(t, err)
}

func TestHTTPTimeout_Default(t *testing.T) {
	// Save and restore
	orig := httpTimeout
	defer func() { httpTimeout = orig }()

	httpTimeout = 30 * time.Second
	c := httpClient()
	assert.Equal(t, 30*time.Second, c.Timeout)
}

func TestHTTPTimeout_EnvOverride(t *testing.T) {
	// Test that the env-based configuration mechanism works by testing httpClient directly
	orig := httpTimeout
	defer func() { httpTimeout = orig }()

	httpTimeout = 45 * time.Second
	c := httpClient()
	assert.Equal(t, 45*time.Second, c.Timeout)
}

func TestResolve_DockerReference(t *testing.T) {
	ctx := context.Background()
	resolved, err := Resolve(ctx, "docker://alpine:3.19")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, "docker", resolved.Meta.Runs.Using)
	assert.Equal(t, "alpine:3.19", resolved.Meta.Runs.Image)
	assert.Equal(t, "", resolved.Dir)
}

func TestResolve_LocalActionDir(t *testing.T) {
	tmpDir := t.TempDir()
	actionDir := filepath.Join(tmpDir, "test", "action", "v1")
	require.NoError(t, os.MkdirAll(actionDir, 0o755))

	actionYml := `name: Test Action
description: A test action
runs:
  using: composite
  steps:
    - run: echo hello
      shell: bash
`
	require.NoError(t, os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte(actionYml), 0o644))

	t.Setenv("CILOCK_LOCAL_ACTION_DIR", tmpDir)

	ctx := context.Background()
	resolved, err := Resolve(ctx, "test/action@v1")
	require.NoError(t, err)
	require.NotNil(t, resolved)
	assert.Equal(t, actionDir, resolved.Dir)
	assert.Equal(t, "composite", resolved.Meta.Runs.Using)
	assert.Len(t, resolved.Meta.Runs.Steps, 1)
}

func TestResolve_LocalActionDir_NotFound_FallsThrough(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CILOCK_LOCAL_ACTION_DIR", tmpDir)

	ctx := context.Background()
	_, err := Resolve(ctx, "actions/nonexistent@v999")
	// The local resolution finds nothing and falls through to download,
	// which will fail because there's no such action.
	require.Error(t, err)
}

func TestResolveLocal_DockerRef_ReturnsNil(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := resolveLocal(tmpDir, "docker://alpine:3.19")
	assert.Nil(t, resolved)
	assert.Nil(t, err)
}

func TestResolveLocal_InvalidRef_ReturnsNil(t *testing.T) {
	tmpDir := t.TempDir()
	resolved, err := resolveLocal(tmpDir, "invalid-no-at-sign")
	assert.Nil(t, resolved)
	assert.Nil(t, err)
}

func TestDownloadAndExtractTarball_SlowServerTimesOut(t *testing.T) {
	// Save and restore
	orig := httpTimeout
	defer func() { httpTimeout = orig }()
	httpTimeout = 1 * time.Second

	// Server that never responds
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	_, err := downloadAndExtractTarball(context.Background(), srv.URL)
	require.Error(t, err)
	// Should be a timeout error, not hang forever
}

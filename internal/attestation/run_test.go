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

package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/cilock-action/internal/config"
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/plugins/attestors/githubaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import git attestor so it's registered for TestRunAction_WithExtraAttestors
	_ "github.com/aflock-ai/rookery/plugins/attestors/git"
)

func TestBuildUnsignedEnvelope_ValidCollection(t *testing.T) {
	collection := attestation.Collection{
		Name: "test-step",
	}

	env, err := buildUnsignedEnvelope(collection)
	require.NoError(t, err)

	assert.Equal(t, intoto.PayloadType, env.PayloadType)
	assert.NotEmpty(t, env.Payload)
	assert.Empty(t, env.Signatures)

	// Verify the payload round-trips through JSON correctly.
	// This simulates what processResults does: json.Marshal the envelope,
	// then consumers base64-decode the payload field from the JSON string.
	envJSON, err := json.Marshal(&env)
	require.NoError(t, err)

	// Parse the raw JSON to get the base64-encoded payload string
	var rawEnv struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	err = json.Unmarshal(envJSON, &rawEnv)
	require.NoError(t, err)

	// Base64-decode the payload (this is what consumers like node scripts do)
	payloadBytes, err := base64.StdEncoding.DecodeString(rawEnv.Payload)
	require.NoError(t, err)

	var stmt map[string]interface{}
	err = json.Unmarshal(payloadBytes, &stmt)
	require.NoError(t, err)

	assert.Equal(t, attestation.CollectionType, stmt["predicateType"])
}

func TestBuildUnsignedEnvelope_EmptyCollection(t *testing.T) {
	collection := attestation.Collection{}

	env, err := buildUnsignedEnvelope(collection)
	require.NoError(t, err)

	// Should still produce valid envelope even with empty collection
	assert.Equal(t, intoto.PayloadType, env.PayloadType)
	assert.NotEmpty(t, env.Payload)
}

func TestBuildUnsignedEnvelope_PredicateType(t *testing.T) {
	collection := attestation.Collection{
		Name: "my-step",
	}

	env, err := buildUnsignedEnvelope(collection)
	require.NoError(t, err)

	// Marshal + unmarshal to simulate what json.Marshal does in processResults
	envJSON, err := json.Marshal(&env)
	require.NoError(t, err)

	// Parse the JSON envelope
	var rawEnv struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	err = json.Unmarshal(envJSON, &rawEnv)
	require.NoError(t, err)

	// Decode the base64 payload
	stmtBytes, err := base64.StdEncoding.DecodeString(rawEnv.Payload)
	require.NoError(t, err)

	// Verify predicate contains step name
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Name string `json:"name"`
		} `json:"predicate"`
	}
	err = json.Unmarshal(stmtBytes, &stmt)
	require.NoError(t, err)

	assert.Equal(t, attestation.CollectionType, stmt.PredicateType)
	assert.Equal(t, "my-step", stmt.Predicate.Name)
}

func TestOutfileSuffix_NoExtension(t *testing.T) {
	// Simulate the outfile naming logic for export attestors
	outfile := "/tmp/attestation"
	attestorName := "parent/child"

	// Apply the naming logic
	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/attestation-parent-child.json", result)
}

func TestOutfileSuffix_WithJsonExtension(t *testing.T) {
	outfile := "/tmp/attestation.json"
	attestorName := "parent/child"

	result := applyAttestorSuffix(outfile, attestorName)
	// Should NOT produce /tmp/attestation.json-parent-child.json
	assert.Equal(t, "/tmp/attestation-parent-child.json", result)
}

func TestOutfileSuffix_EmptyAttestorName(t *testing.T) {
	outfile := "/tmp/attestation.json"
	attestorName := ""

	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/attestation.json", result)
}

func TestOutfileSuffix_NestedSlashes(t *testing.T) {
	outfile := "/tmp/out.json"
	attestorName := "a/b/c"

	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/out-a-b-c.json", result)
}

func TestOutfileSuffix_NonJsonExtension(t *testing.T) {
	outfile := "/tmp/attestation.txt"
	attestorName := "export"

	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/attestation-export.txt", result)
}

// --- Builder function tests ---

func TestBuildSigners_NoSigners(t *testing.T) {
	cfg := &config.Config{
		EnableSigstore: false,
		KeyPath:        "",
	}
	signers, err := buildSigners(context.Background(), cfg)
	require.NoError(t, err)
	assert.Empty(t, signers)
}

func TestBuildSigners_FileOnly_InvalidKey(t *testing.T) {
	// With a non-existent key file, buildSigners should error
	cfg := &config.Config{
		EnableSigstore: false,
		KeyPath:        "/nonexistent/key.pem",
	}
	_, err := buildSigners(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create file signer")
}

func TestBuildTimestampers_Empty(t *testing.T) {
	cfg := &config.Config{
		TimestampServers: nil,
	}
	ts := buildTimestampers(cfg)
	assert.Empty(t, ts)
}

func TestBuildTimestampers_Multiple(t *testing.T) {
	cfg := &config.Config{
		TimestampServers: []string{
			"https://tsa1.example.com",
			"https://tsa2.example.com",
			"https://tsa3.example.com",
		},
	}
	ts := buildTimestampers(cfg)
	assert.Len(t, ts, 3)
}

func TestBuildAttestors_CommandOnly(t *testing.T) {
	cfg := &config.Config{}
	attestors, err := buildAttestors(cfg, []string{"go", "test", "./..."})
	require.NoError(t, err)

	// Should have product, material, and commandrun
	assert.Len(t, attestors, 3)
}

func TestBuildAttestors_NoCommand(t *testing.T) {
	cfg := &config.Config{}
	attestors, err := buildAttestors(cfg, nil)
	require.NoError(t, err)

	// Should have only product and material
	assert.Len(t, attestors, 2)
}

func TestBuildAttestors_UnknownAttestor(t *testing.T) {
	cfg := &config.Config{
		Attestations: []string{"nonexistent-attestor"},
	}
	_, err := buildAttestors(cfg, []string{"echo", "hi"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown attestor")
}

func TestBuildAttestors_SkipDuplicates(t *testing.T) {
	cfg := &config.Config{
		Attestations: []string{"command-run", "material", "product"},
	}
	attestors, err := buildAttestors(cfg, []string{"echo", "hi"})
	require.NoError(t, err)

	// Should still be just 3: product + material + commandrun (dupes skipped)
	assert.Len(t, attestors, 3)
}

func TestBuildAttestationOpts_WorkingDir(t *testing.T) {
	cfg := &config.Config{
		WorkingDir: "/tmp/workdir",
	}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	assert.Len(t, opts, 1)
}

func TestBuildAttestationOpts_Hashes(t *testing.T) {
	cfg := &config.Config{
		Hashes: []string{"sha256", "sha1"},
	}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	assert.Len(t, opts, 1)
}

func TestBuildAttestationOpts_InvalidHash(t *testing.T) {
	cfg := &config.Config{
		Hashes: []string{"not-a-real-hash"},
	}
	_, err := buildAttestationOpts(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hash algorithm")
}

func TestBuildAttestationOpts_EnvFilter(t *testing.T) {
	cfg := &config.Config{
		EnvFilterSensitiveVars: true,
		EnvAddSensitiveKey:     []string{"MY_SECRET"},
	}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	assert.Len(t, opts, 2)
}

func TestBuildAttestationOpts_Empty(t *testing.T) {
	cfg := &config.Config{}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	assert.Empty(t, opts)
}

// --- processResults tests ---

func TestProcessResults_EmptyResults(t *testing.T) {
	cfg := &config.Config{}
	result, err := processResults(context.Background(), cfg, nil)
	require.NoError(t, err)
	assert.Empty(t, result.GitOIDs)
	assert.Empty(t, result.AttestationFiles)
}

func TestProcessResults_WithSignedEnvelope_NoOutfile(t *testing.T) {
	// When there's no outfile, processResults prints to stdout
	cfg := &config.Config{
		EnableArchivista: false,
	}

	envelope := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     []byte("test-payload"),
		Signatures:  []dsse.Signature{},
	}

	results := []workflow.RunResult{
		{
			SignedEnvelope: envelope,
			AttestorName:   "",
		},
	}

	result, err := processResults(context.Background(), cfg, results)
	require.NoError(t, err)
	assert.Empty(t, result.AttestationFiles)
	assert.Empty(t, result.GitOIDs)
}

func TestProcessResults_WithOutfile(t *testing.T) {
	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		OutFile:          outfile,
		EnableArchivista: false,
	}

	envelope := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     []byte("test-payload"),
		Signatures:  []dsse.Signature{},
	}

	results := []workflow.RunResult{
		{
			SignedEnvelope: envelope,
			AttestorName:   "test-attestor",
		},
	}

	result, err := processResults(context.Background(), cfg, results)
	require.NoError(t, err)

	// Should have created a file with the attestor suffix
	require.Len(t, result.AttestationFiles, 1)
	assert.Contains(t, result.AttestationFiles[0], "test-attestor")

	// File should exist and contain valid JSON
	data, err := os.ReadFile(result.AttestationFiles[0])
	require.NoError(t, err)
	var parsed dsse.Envelope
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, intoto.PayloadType, parsed.PayloadType)
}

func TestProcessResults_InsecureMode_BuildsUnsignedEnvelope(t *testing.T) {
	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		OutFile:          outfile,
		EnableArchivista: false,
	}

	// Simulate insecure mode: empty envelope but non-empty collection
	results := []workflow.RunResult{
		{
			SignedEnvelope: dsse.Envelope{}, // zero-value
			Collection: attestation.Collection{
				Name: "test-step",
			},
			AttestorName: "insecure",
		},
	}

	result, err := processResults(context.Background(), cfg, results)
	require.NoError(t, err)
	require.Len(t, result.AttestationFiles, 1)

	// Verify the generated envelope has the proper structure
	data, err := os.ReadFile(result.AttestationFiles[0])
	require.NoError(t, err)

	var parsed dsse.Envelope
	require.NoError(t, json.Unmarshal(data, &parsed))
	assert.Equal(t, intoto.PayloadType, parsed.PayloadType)
	assert.NotEmpty(t, parsed.Payload)
	assert.Empty(t, parsed.Signatures)
}

func TestProcessResults_MultipleResults(t *testing.T) {
	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		OutFile:          outfile,
		EnableArchivista: false,
	}

	envelope := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     []byte("payload"),
		Signatures:  []dsse.Signature{},
	}

	results := []workflow.RunResult{
		{SignedEnvelope: envelope, AttestorName: "first"},
		{SignedEnvelope: envelope, AttestorName: "second"},
	}

	result, err := processResults(context.Background(), cfg, results)
	require.NoError(t, err)
	assert.Len(t, result.AttestationFiles, 2)
}

func TestProcessResults_InvalidOutfilePath(t *testing.T) {
	cfg := &config.Config{
		OutFile:          "/nonexistent/dir/attestation.json",
		EnableArchivista: false,
	}

	envelope := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     []byte("payload"),
	}

	results := []workflow.RunResult{
		{SignedEnvelope: envelope, AttestorName: "test"},
	}

	_, err := processResults(context.Background(), cfg, results)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write attestation")
}

// --- buildSigners deeper tests ---

func TestBuildSigners_FileSigner_WithCertAndIntermediates(t *testing.T) {
	// File paths don't exist, so signer creation will fail,
	// but this exercises the option-building branches
	cfg := &config.Config{
		EnableSigstore:    false,
		KeyPath:           "/nonexistent/key.pem",
		CertificatePath:   "/nonexistent/cert.pem",
		IntermediatePaths: []string{"/nonexistent/intermediate1.pem", "/nonexistent/intermediate2.pem"},
	}
	_, err := buildSigners(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create file signer")
}

func TestBuildSigners_SigstoreEnabled_FailsWithoutOIDC(t *testing.T) {
	// Fulcio signer will fail without proper OIDC setup, but this
	// exercises the fulcio option-building branches
	cfg := &config.Config{
		EnableSigstore:     true,
		FulcioURL:          "https://fulcio.example.com",
		FulcioOIDCIssuer:   "https://issuer.example.com",
		FulcioOIDCClientID: "test-client",
		FulcioToken:        "fake-token",
		FulcioUseHTTP:      true,
	}
	_, err := buildSigners(context.Background(), cfg)
	// Will fail because OIDC/Fulcio isn't reachable, but it exercises all branches
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fulcio")
}

// --- buildAttestationOpts deeper tests ---

func TestBuildAttestationOpts_AllOptions(t *testing.T) {
	cfg := &config.Config{
		WorkingDir:             "/tmp/work",
		Hashes:                 []string{"sha256"},
		EnvFilterSensitiveVars: true,
		EnvAddSensitiveKey:     []string{"SECRET1", "SECRET2"},
	}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	// WorkingDir + Hashes + EnvFilter + EnvAddKeys = 4
	assert.Len(t, opts, 4)
}

func TestBuildAttestationOpts_OnlyEnvKeys(t *testing.T) {
	cfg := &config.Config{
		EnvAddSensitiveKey: []string{"MY_KEY"},
	}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	assert.Len(t, opts, 1)
}

func TestBuildAttestationOpts_GitOIDHash(t *testing.T) {
	cfg := &config.Config{
		Hashes: []string{"gitoid:sha256"},
	}
	opts, err := buildAttestationOpts(cfg)
	require.NoError(t, err)
	assert.Len(t, opts, 1)
}

// --- buildAttestors deeper tests ---

func TestBuildAttestors_EmptyAttestations(t *testing.T) {
	cfg := &config.Config{
		Attestations: []string{},
	}
	attestors, err := buildAttestors(cfg, []string{"echo"})
	require.NoError(t, err)
	// product + material + commandrun = 3
	assert.Len(t, attestors, 3)
}

func TestBuildAttestors_EmptyCommand(t *testing.T) {
	cfg := &config.Config{
		Attestations: []string{},
	}
	attestors, err := buildAttestors(cfg, []string{})
	require.NoError(t, err)
	// Empty command slice (len 0) does not add commandrun
	assert.Len(t, attestors, 2)
}

func TestBuildTimestampers_SingleServer(t *testing.T) {
	cfg := &config.Config{
		TimestampServers: []string{"https://tsa.example.com"},
	}
	ts := buildTimestampers(cfg)
	assert.Len(t, ts, 1)
}

// --- End-to-end Run / RunAction / storeInArchivista tests ---

func TestRun_InsecureMode_CommandEchoHello(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Command: "echo hello",
		Step:    "test-step",
		OutFile: outFile,
	}

	result, err := Run(context.Background(), cfg, []string{"sh", "-c", "echo hello"})
	require.NoError(t, err)
	require.Len(t, result.AttestationFiles, 1)

	// Read and parse the attestation file
	data, err := os.ReadFile(result.AttestationFiles[0])
	require.NoError(t, err)

	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Equal(t, intoto.PayloadType, env.PayloadType)

	// After json.Unmarshal, env.Payload is the raw JSON bytes (Go's JSON
	// encoder base64-encodes []byte on write, and the decoder reverses that
	// on read). Parse directly as JSON to verify the step name.
	var stmt map[string]interface{}
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))

	predicate, ok := stmt["predicate"].(map[string]interface{})
	require.True(t, ok, "predicate should be a map")
	assert.Equal(t, "test-step", predicate["name"])
}

func TestRun_InsecureMode_FailingCommand(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Command: "false",
		Step:    "fail-step",
		OutFile: outFile,
	}

	_, err := Run(context.Background(), cfg, []string{"sh", "-c", "false"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation run failed")
}

func TestRunAction_InsecureMode(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Step:    "action-step",
		OutFile: outFile,
	}

	actionCfg := &ActionConfig{
		Ref:       "test/action@v1",
		Type:      "composite",
		Name:      "Test Action",
		Dir:       t.TempDir(),
		Inputs:    map[string]string{"foo": "bar"},
		RefPinned: true,
	}

	actionFn := func(ctx context.Context) (int, error) {
		return 0, nil
	}

	result, err := RunAction(context.Background(), cfg, actionCfg, actionFn)
	require.NoError(t, err)
	require.Len(t, result.AttestationFiles, 1)

	// Read and verify the attestation file is a valid DSSE envelope
	data, err := os.ReadFile(result.AttestationFiles[0])
	require.NoError(t, err)

	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Equal(t, intoto.PayloadType, env.PayloadType)
}

func TestRunAction_ActionFnReturnsError(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Step:    "action-step",
		OutFile: outFile,
	}

	actionCfg := &ActionConfig{
		Ref:       "test/action@v1",
		Type:      "composite",
		Name:      "Test Action",
		Dir:       t.TempDir(),
		Inputs:    map[string]string{},
		RefPinned: false,
	}

	actionFn := func(ctx context.Context) (int, error) {
		return 1, fmt.Errorf("action failed")
	}

	_, err := RunAction(context.Background(), cfg, actionCfg, actionFn)
	require.Error(t, err)
}

func TestRunAction_WithDockerConfig(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Step:    "docker-action-step",
		OutFile: outFile,
	}

	actionCfg := &ActionConfig{
		Ref:       "test/docker-action@v1",
		Type:      "docker",
		Name:      "Docker Test Action",
		Dir:       t.TempDir(),
		Inputs:    map[string]string{"input1": "value1"},
		RefPinned: true,
		DockerConfigFn: func() *githubaction.DockerContainerConfig {
			return &githubaction.DockerContainerConfig{
				Image:      "alpine:3.18",
				Entrypoint: "/entrypoint.sh",
				Network:    "host",
			}
		},
	}

	actionFn := func(ctx context.Context) (int, error) {
		return 0, nil
	}

	result, err := RunAction(context.Background(), cfg, actionCfg, actionFn)
	require.NoError(t, err)
	require.Len(t, result.AttestationFiles, 1)

	// Verify the attestation file was created and is valid JSON
	data, err := os.ReadFile(result.AttestationFiles[0])
	require.NoError(t, err)

	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(data, &env))
	assert.Equal(t, intoto.PayloadType, env.PayloadType)
}

func TestStoreInArchivista_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/upload", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"gitoid": "abc123deadbeef"})
	}))
	defer server.Close()

	cfg := &config.Config{
		ArchivistaServer: server.URL,
	}

	r := workflow.RunResult{
		SignedEnvelope: dsse.Envelope{
			PayloadType: intoto.PayloadType,
			Payload:     []byte("test-payload"),
			Signatures:  []dsse.Signature{},
		},
	}

	gitoid, err := storeInArchivista(context.Background(), cfg, r)
	require.NoError(t, err)
	assert.Equal(t, "abc123deadbeef", gitoid)
}

func TestStoreInArchivista_WithHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the custom headers were forwarded
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "value", r.Header.Get("X-Custom"))

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"gitoid": "header-gitoid"})
	}))
	defer server.Close()

	cfg := &config.Config{
		ArchivistaServer:  server.URL,
		ArchivistaHeaders: []string{"Authorization: Bearer test-token", "X-Custom: value"},
	}

	r := workflow.RunResult{
		SignedEnvelope: dsse.Envelope{
			PayloadType: intoto.PayloadType,
			Payload:     []byte("test-payload"),
			Signatures:  []dsse.Signature{},
		},
	}

	gitoid, err := storeInArchivista(context.Background(), cfg, r)
	require.NoError(t, err)
	assert.Equal(t, "header-gitoid", gitoid)
}

func TestStoreInArchivista_InvalidHeader(t *testing.T) {
	cfg := &config.Config{
		ArchivistaServer:  "http://unused.example.com",
		ArchivistaHeaders: []string{"invalid-no-colon"},
	}

	r := workflow.RunResult{
		SignedEnvelope: dsse.Envelope{
			PayloadType: intoto.PayloadType,
			Payload:     []byte("test-payload"),
		},
	}

	_, err := storeInArchivista(context.Background(), cfg, r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid archivista header")
}

func TestStoreInArchivista_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	cfg := &config.Config{
		ArchivistaServer: server.URL,
	}

	r := workflow.RunResult{
		SignedEnvelope: dsse.Envelope{
			PayloadType: intoto.PayloadType,
			Payload:     []byte("test-payload"),
		},
	}

	_, err := storeInArchivista(context.Background(), cfg, r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestProcessResults_WithArchivista(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"gitoid": "archivista-gitoid-123"})
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		OutFile:          outfile,
		EnableArchivista: true,
		ArchivistaServer: server.URL,
	}

	envelope := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     []byte("test-payload"),
		Signatures:  []dsse.Signature{},
	}

	results := []workflow.RunResult{
		{
			SignedEnvelope: envelope,
			AttestorName:   "with-archivista",
		},
	}

	result, err := processResults(context.Background(), cfg, results)
	require.NoError(t, err)
	require.Len(t, result.AttestationFiles, 1)
	require.Len(t, result.GitOIDs, 1)
	assert.Equal(t, "archivista-gitoid-123", result.GitOIDs[0])
}

func TestProcessResults_ArchivistaError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		OutFile:          outfile,
		EnableArchivista: true,
		ArchivistaServer: server.URL,
	}

	envelope := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     []byte("test-payload"),
		Signatures:  []dsse.Signature{},
	}

	results := []workflow.RunResult{
		{
			SignedEnvelope: envelope,
			AttestorName:   "archivista-fail",
		},
	}

	_, err := processResults(context.Background(), cfg, results)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store in archivista")
}

func TestRunAction_WithExtraAttestors(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Step:         "extra-attestors",
		OutFile:      outFile,
		Attestations: []string{"git"},
	}

	actionCfg := &ActionConfig{
		Ref:       "test/action@v1",
		Type:      "composite",
		Name:      "Test",
		Dir:       t.TempDir(),
		Inputs:    map[string]string{},
		RefPinned: false,
	}

	result, err := RunAction(context.Background(), cfg, actionCfg, func(ctx context.Context) (int, error) {
		return 0, nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.AttestationFiles)
}

func TestRunAction_UnknownExtraAttestor(t *testing.T) {
	attestation.RegisterLegacyAliases()

	cfg := &config.Config{
		Step:         "bad-attestor",
		OutFile:      filepath.Join(t.TempDir(), "att.json"),
		Attestations: []string{"nonexistent-attestor-xyz"},
	}

	actionCfg := &ActionConfig{
		Ref:  "test/action@v1",
		Type: "composite",
		Name: "Test",
		Dir:  t.TempDir(),
	}

	_, err := RunAction(context.Background(), cfg, actionCfg, func(ctx context.Context) (int, error) {
		return 0, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown attestor")
}

func TestRunAction_SkipDuplicateAttestors(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "attestation.json")

	cfg := &config.Config{
		Step:         "dup-attestors",
		OutFile:      outFile,
		Attestations: []string{"command-run", "material", "product", "github-action"},
	}

	actionCfg := &ActionConfig{
		Ref:       "test/action@v1",
		Type:      "composite",
		Name:      "Test",
		Dir:       t.TempDir(),
		Inputs:    map[string]string{},
		RefPinned: true,
	}

	result, err := RunAction(context.Background(), cfg, actionCfg, func(ctx context.Context) (int, error) {
		return 0, nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.AttestationFiles)
}

func TestRun_WithOutfileDir(t *testing.T) {
	attestation.RegisterLegacyAliases()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "subdir", "attestation.json")

	// Create the subdirectory so the file can be written
	require.NoError(t, os.MkdirAll(filepath.Dir(outFile), 0o755))

	cfg := &config.Config{
		Command: "echo test",
		Step:    "outfile-step",
		OutFile: outFile,
	}

	result, err := Run(context.Background(), cfg, []string{"sh", "-c", "echo test"})
	require.NoError(t, err)
	require.NotEmpty(t, result.AttestationFiles)

	// Verify the file actually exists on disk
	for _, f := range result.AttestationFiles {
		_, err := os.Stat(f)
		assert.NoError(t, err, "attestation file should exist: %s", f)
	}
}

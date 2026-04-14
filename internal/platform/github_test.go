package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearAllGitHubInputs ensures no INPUT_* vars leak between tests.
func clearAllGitHubInputs(t *testing.T) {
	t.Helper()
	inputs := []string{
		"INPUT_COMMAND", "INPUT_ACTION_REF", "INPUT_STEP",
		"INPUT_VERSION", "INPUT_CILOCK_BINARY_URL",
		"INPUT_OUTFILE", "INPUT_WORKINGDIR", "INPUT_TRACE",
		"INPUT_ATTESTATIONS", "INPUT_HASHES",
		"INPUT_ENABLE_ARCHIVISTA", "INPUT_ARCHIVISTA_SERVER",
		"INPUT_ENABLE_SIGSTORE", "INPUT_FULCIO_URL",
		"INPUT_FULCIO_OIDC_CLIENT_ID", "INPUT_FULCIO_OIDC_ISSUER",
		"INPUT_KEY", "INPUT_CERTIFICATE", "INPUT_INTERMEDIATES",
		"INPUT_KMS_REF", "INPUT_KMS_AWS_PROFILE", "INPUT_KMS_GCP_CREDENTIALS_FILE",
		"INPUT_VAULT_URL", "INPUT_VAULT_TOKEN",
		"INPUT_TIMESTAMP_SERVERS",
		"INPUT_ENV_FILTER_SENSITIVE_VARS", "INPUT_ENV_ADD_SENSITIVE_KEY",
		"INPUT_CILOCK_ARGS",
		"INPUT_PRODUCT_INCLUDE_GLOB", "INPUT_PRODUCT_EXCLUDE_GLOB",
		"INPUT_ATTESTOR_SBOM_EXPORT", "INPUT_ATTESTOR_SLSA_EXPORT",
		"INPUT_BUILDER_MANIFEST", "INPUT_BUILDER_PRESET",
		"INPUT_ACTION_INPUTS", "INPUT_ACTION_ENV",
		"INPUT_ACTION-REF", // hyphenated variant
		"INPUT_FULCIO_TOKEN",
		"TESTIFYSEC_API_KEY",
	}
	for _, key := range inputs {
		t.Setenv(key, "")
	}
}

func TestParseGitHub_MinimalCommand(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_COMMAND", "go test ./...")
	t.Setenv("INPUT_STEP", "test")

	cfg, err := ParseGitHub()
	require.NoError(t, err)

	assert.Equal(t, "go test ./...", cfg.Command)
	assert.Equal(t, "", cfg.ActionRef)
	assert.Equal(t, "test", cfg.Step)
}

func TestParseGitHub_Defaults(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")

	cfg, err := ParseGitHub()
	require.NoError(t, err)

	// Check defaults are applied
	assert.Equal(t, DefaultArchivistaServer, cfg.ArchivistaServer)
	assert.Equal(t, DefaultFulcioURL, cfg.FulcioURL)
	assert.Equal(t, DefaultFulcioOIDCClientID, cfg.FulcioOIDCClientID)
	assert.Equal(t, DefaultFulcioOIDCIssuer, cfg.FulcioOIDCIssuer)
	assert.Equal(t, DefaultProductIncludeGlob, cfg.ProductIncludeGlob)
	assert.True(t, cfg.EnableArchivista, "archivista should default to true")
	assert.True(t, cfg.EnableSigstore, "sigstore should default to true")

	// Default attestations
	assert.Equal(t, []string{"environment", "git", "github"}, cfg.Attestations)

	// Default hashes
	assert.Equal(t, []string{"sha256"}, cfg.Hashes)

	// Default timestamp servers
	assert.Equal(t, []string{DefaultTimestampServer}, cfg.TimestampServers)
}

func TestParseGitHub_CustomAttestations(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_ATTESTATIONS", "environment git slsa")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, []string{"environment", "git", "slsa"}, cfg.Attestations)
}

func TestParseGitHub_BooleanInputs(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_TRACE", "true")
	t.Setenv("INPUT_ENV_FILTER_SENSITIVE_VARS", "TRUE")
	t.Setenv("INPUT_ATTESTOR_SBOM_EXPORT", "True")
	t.Setenv("INPUT_ATTESTOR_SLSA_EXPORT", "false")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.True(t, cfg.Trace)
	assert.True(t, cfg.EnvFilterSensitiveVars)
	assert.True(t, cfg.AttestorSBOMExport)
	assert.False(t, cfg.AttestorSLSAExport)
}

func TestParseGitHub_BoolDefaultsOverride(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_ENABLE_ARCHIVISTA", "false")
	t.Setenv("INPUT_ENABLE_SIGSTORE", "false")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.False(t, cfg.EnableArchivista)
	assert.False(t, cfg.EnableSigstore)
}

func TestParseGitHub_Intermediates(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_INTERMEDIATES", "cert1.pem,cert2.pem,cert3.pem")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, []string{"cert1.pem", "cert2.pem", "cert3.pem"}, cfg.IntermediatePaths)
}

func TestParseGitHub_CilockArgs(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_CILOCK_ARGS", "--verbose --dry-run")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, []string{"--verbose", "--dry-run"}, cfg.CilockArgs)
}

func TestParseGitHub_EnvAddSensitiveKey(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_ENV_ADD_SENSITIVE_KEY", "AWS_SECRET,GITHUB_TOKEN")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, []string{"AWS_SECRET", "GITHUB_TOKEN"}, cfg.EnvAddSensitiveKey)
}

func TestParseGitHub_APIKeyAutoInject(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("TESTIFYSEC_API_KEY", "my-secret-key")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	require.Len(t, cfg.ArchivistaHeaders, 1)
	assert.Equal(t, "Authorization: Bearer my-secret-key", cfg.ArchivistaHeaders[0])
}

func TestParseGitHub_NoAPIKey(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Empty(t, cfg.ArchivistaHeaders)
}

func TestParseGitHub_ActionInputsJSON(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_ACTION_REF", "actions/checkout@v4")
	t.Setenv("INPUT_ACTION_INPUTS", `{"fetch-depth": "0", "token": "abc123"}`)

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	require.NotNil(t, cfg.ActionInputs)
	assert.Equal(t, "0", cfg.ActionInputs["fetch-depth"])
	assert.Equal(t, "abc123", cfg.ActionInputs["token"])
}

func TestParseGitHub_ActionInputsInvalidJSON(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_ACTION_REF", "actions/checkout@v4")
	t.Setenv("INPUT_ACTION_INPUTS", "not valid json")

	_, err := ParseGitHub()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse action-inputs")
}

func TestParseGitHub_ActionEnv(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_ACTION_ENV", "FOO=bar\nBAZ=qux")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	require.NotNil(t, cfg.ActionEnv)
	assert.Equal(t, "bar", cfg.ActionEnv["FOO"])
	assert.Equal(t, "qux", cfg.ActionEnv["BAZ"])
}

func TestParseGitHub_ActionEnvWithEmptyLines(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_ACTION_ENV", "FOO=bar\n\n\nBAZ=qux\n")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	require.NotNil(t, cfg.ActionEnv)
	assert.Len(t, cfg.ActionEnv, 2)
	assert.Equal(t, "bar", cfg.ActionEnv["FOO"])
	assert.Equal(t, "qux", cfg.ActionEnv["BAZ"])
}

func TestParseGitHub_WhitespaceTrimmingOnInputs(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "  test  ")
	t.Setenv("INPUT_COMMAND", "  echo hi  ")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, "test", cfg.Step)
	assert.Equal(t, "echo hi", cfg.Command)
}

func TestParseGitHub_AllSignerFields(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_KEY", "/path/to/key.pem")
	t.Setenv("INPUT_CERTIFICATE", "/path/to/cert.pem")
	t.Setenv("INPUT_KMS_REF", "awskms:///alias/my-key")
	t.Setenv("INPUT_KMS_AWS_PROFILE", "prod")
	t.Setenv("INPUT_KMS_GCP_CREDENTIALS_FILE", "/path/to/creds.json")
	t.Setenv("INPUT_VAULT_URL", "https://vault.example.com")
	t.Setenv("INPUT_VAULT_TOKEN", "s.abc123")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, "/path/to/key.pem", cfg.KeyPath)
	assert.Equal(t, "/path/to/cert.pem", cfg.CertificatePath)
	assert.Equal(t, "awskms:///alias/my-key", cfg.KMSRef)
	assert.Equal(t, "prod", cfg.KMSAWSProfile)
	assert.Equal(t, "/path/to/creds.json", cfg.KMSGCPCredsFile)
	assert.Equal(t, "https://vault.example.com", cfg.VaultURL)
	assert.Equal(t, "s.abc123", cfg.VaultToken)
}

func TestParseGitHub_MultipleHashes(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_HASHES", "sha256 sha512 md5")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, []string{"sha256", "sha512", "md5"}, cfg.Hashes)
}

func TestParseGitHub_MultipleTimestampServers(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_TIMESTAMP_SERVERS", "https://tsa1.example.com https://tsa2.example.com")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, []string{"https://tsa1.example.com", "https://tsa2.example.com"}, cfg.TimestampServers)
}

func TestGhInput_HyphenatedInputNames(t *testing.T) {
	clearAllGitHubInputs(t)
	// GitHub Actions preserves hyphens in input names:
	// "action-ref" → INPUT_ACTION-REF (not INPUT_ACTION_REF)
	// ghInput should try both variants.

	// Set hyphenated version (as GitHub Actions does)
	t.Setenv("INPUT_ACTION-REF", "actions/setup-node@v4")

	result := ghInput("ACTION_REF")
	assert.Equal(t, "actions/setup-node@v4", result, "should find INPUT_ACTION-REF when queried as ACTION_REF")
}

func TestGhInput_UnderscorePreferred(t *testing.T) {
	clearAllGitHubInputs(t)
	// When both variants exist, underscore is tried first
	t.Setenv("INPUT_ACTION_REF", "underscore-value")
	t.Setenv("INPUT_ACTION-REF", "hyphen-value")

	result := ghInput("ACTION_REF")
	assert.Equal(t, "underscore-value", result, "underscore variant should take precedence")
}

func TestGhInput_NoUnderscoreSkipsHyphenLookup(t *testing.T) {
	clearAllGitHubInputs(t)
	// When name has no underscores, hyphenated lookup is skipped (same key)
	t.Setenv("INPUT_COMMAND", "echo hi")

	result := ghInput("COMMAND")
	assert.Equal(t, "echo hi", result)

	// Unset should return empty
	t.Setenv("INPUT_COMMAND", "")
	result = ghInput("COMMAND")
	assert.Equal(t, "", result)
}

func TestParseGitHub_BuilderFields(t *testing.T) {
	clearAllGitHubInputs(t)

	t.Setenv("INPUT_STEP", "test")
	t.Setenv("INPUT_COMMAND", "echo hi")
	t.Setenv("INPUT_BUILDER_MANIFEST", "builder.yaml")
	t.Setenv("INPUT_BUILDER_PRESET", "cicd")

	cfg, err := ParseGitHub()
	require.NoError(t, err)
	assert.Equal(t, "builder.yaml", cfg.BuilderManifest)
	assert.Equal(t, "cicd", cfg.BuilderPreset)
}

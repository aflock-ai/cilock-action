package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearAllGitLabInputs ensures no CILOCK_* vars leak between tests.
func clearAllGitLabInputs(t *testing.T) {
	t.Helper()
	inputs := []string{
		"CILOCK_COMMAND", "CILOCK_ACTION_REF", "CILOCK_STEP",
		"CILOCK_OUTFILE", "CILOCK_WORKINGDIR", "CILOCK_TRACE",
		"CILOCK_ATTESTATIONS", "CILOCK_HASHES",
		"CILOCK_ENABLE_ARCHIVISTA", "CILOCK_ARCHIVISTA_SERVER",
		"CILOCK_ENABLE_SIGSTORE", "CILOCK_FULCIO_URL",
		"CILOCK_FULCIO_OIDC_CLIENT_ID", "CILOCK_FULCIO_OIDC_ISSUER",
		"CILOCK_FULCIO_TOKEN",
		"CILOCK_KEY", "CILOCK_CERTIFICATE", "CILOCK_INTERMEDIATES",
		"CILOCK_KMS_REF", "CILOCK_KMS_AWS_PROFILE", "CILOCK_KMS_GCP_CREDENTIALS_FILE",
		"CILOCK_VAULT_URL", "CILOCK_VAULT_TOKEN",
		"CILOCK_TIMESTAMP_SERVERS",
		"CILOCK_ENV_FILTER_SENSITIVE_VARS", "CILOCK_ENV_ADD_SENSITIVE_KEY",
		"CILOCK_ARGS",
		"CILOCK_PRODUCT_INCLUDE_GLOB", "CILOCK_PRODUCT_EXCLUDE_GLOB",
		"TESTIFYSEC_API_KEY",
	}
	for _, key := range inputs {
		t.Setenv(key, "")
	}
}

func TestParseGitLab_MinimalCommand(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_COMMAND", "go test ./...")
	t.Setenv("CILOCK_STEP", "test")

	cfg, err := ParseGitLab()
	require.NoError(t, err)

	assert.Equal(t, "go test ./...", cfg.Command)
	assert.Equal(t, "", cfg.ActionRef)
	assert.Equal(t, "test", cfg.Step)
}

func TestParseGitLab_Defaults(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")

	cfg, err := ParseGitLab()
	require.NoError(t, err)

	assert.Equal(t, DefaultArchivistaServer, cfg.ArchivistaServer)
	assert.Equal(t, DefaultFulcioURL, cfg.FulcioURL)
	assert.Equal(t, DefaultProductIncludeGlob, cfg.ProductIncludeGlob)
	assert.True(t, cfg.EnableArchivista, "archivista should default to true")

	// Default attestations for GitLab include "gitlab" not "github"
	assert.Equal(t, []string{"environment", "git", "gitlab"}, cfg.Attestations)

	// Default hashes
	assert.Equal(t, []string{"sha256"}, cfg.Hashes)

	// Default timestamp servers
	assert.Equal(t, []string{DefaultTimestampServer}, cfg.TimestampServers)
}

func TestParseGitLab_SigstoreDefaultsFalse(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")

	cfg, err := ParseGitLab()
	require.NoError(t, err)

	// GitLab doesn't have native OIDC for sigstore, so defaults to false
	assert.False(t, cfg.EnableSigstore, "sigstore should default to false on GitLab")
}

func TestParseGitLab_CustomAttestations(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")
	t.Setenv("CILOCK_ATTESTATIONS", "environment git slsa")

	cfg, err := ParseGitLab()
	require.NoError(t, err)
	assert.Equal(t, []string{"environment", "git", "slsa"}, cfg.Attestations)
}

func TestParseGitLab_BooleanParsing(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")
	t.Setenv("CILOCK_TRACE", "true")
	t.Setenv("CILOCK_ENV_FILTER_SENSITIVE_VARS", "TRUE")
	t.Setenv("CILOCK_ENABLE_SIGSTORE", "True")

	cfg, err := ParseGitLab()
	require.NoError(t, err)
	assert.True(t, cfg.Trace)
	assert.True(t, cfg.EnvFilterSensitiveVars)
	assert.True(t, cfg.EnableSigstore, "case-insensitive 'True' should enable sigstore")
}

func TestParseGitLab_Intermediates(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")
	t.Setenv("CILOCK_INTERMEDIATES", "cert1.pem,cert2.pem,cert3.pem")

	cfg, err := ParseGitLab()
	require.NoError(t, err)
	assert.Equal(t, []string{"cert1.pem", "cert2.pem", "cert3.pem"}, cfg.IntermediatePaths)
}

func TestParseGitLab_SensitiveKeys(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")
	t.Setenv("CILOCK_ENV_ADD_SENSITIVE_KEY", "AWS_SECRET,GITHUB_TOKEN")

	cfg, err := ParseGitLab()
	require.NoError(t, err)
	assert.Equal(t, []string{"AWS_SECRET", "GITHUB_TOKEN"}, cfg.EnvAddSensitiveKey)
}

func TestParseGitLab_APIKeyInjection(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")
	t.Setenv("TESTIFYSEC_API_KEY", "my-secret-key")

	cfg, err := ParseGitLab()
	require.NoError(t, err)
	require.Len(t, cfg.ArchivistaHeaders, 1)
	assert.Equal(t, "Authorization: Token my-secret-key", cfg.ArchivistaHeaders[0])
}

func TestParseGitLab_AllSignerFields(t *testing.T) {
	clearAllGitLabInputs(t)

	t.Setenv("CILOCK_STEP", "test")
	t.Setenv("CILOCK_COMMAND", "echo hi")
	t.Setenv("CILOCK_KEY", "/path/to/key.pem")
	t.Setenv("CILOCK_CERTIFICATE", "/path/to/cert.pem")
	t.Setenv("CILOCK_KMS_REF", "awskms:///alias/my-key")
	t.Setenv("CILOCK_KMS_AWS_PROFILE", "prod")
	t.Setenv("CILOCK_KMS_GCP_CREDENTIALS_FILE", "/path/to/creds.json")
	t.Setenv("CILOCK_VAULT_URL", "https://vault.example.com")
	t.Setenv("CILOCK_VAULT_TOKEN", "s.abc123")

	cfg, err := ParseGitLab()
	require.NoError(t, err)
	assert.Equal(t, "/path/to/key.pem", cfg.KeyPath)
	assert.Equal(t, "/path/to/cert.pem", cfg.CertificatePath)
	assert.Equal(t, "awskms:///alias/my-key", cfg.KMSRef)
	assert.Equal(t, "prod", cfg.KMSAWSProfile)
	assert.Equal(t, "/path/to/creds.json", cfg.KMSGCPCredsFile)
	assert.Equal(t, "https://vault.example.com", cfg.VaultURL)
	assert.Equal(t, "s.abc123", cfg.VaultToken)
}

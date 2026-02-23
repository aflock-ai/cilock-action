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

package platform

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/cilock-action/internal/config"
)

// GitHub default values matching the action.yml spec.
const (
	DefaultAttestations       = "environment git github"
	DefaultHashes             = "sha256"
	DefaultArchivistaServer   = "https://web.platform.testifysec.com"
	DefaultFulcioURL          = "https://fulcio.platform.testifysec.com"
	DefaultFulcioOIDCClientID = "sigstore"
	DefaultFulcioOIDCIssuer   = "https://token.actions.githubusercontent.com"
	DefaultTimestampServer    = "https://tsa.platform.testifysec.com/api/v1/timestamp"
	DefaultProductIncludeGlob = "*"
)

// ParseGitHub populates a Config from GitHub Actions INPUT_* environment variables.
func ParseGitHub() (*config.Config, error) {
	c := &config.Config{
		// Core
		Command:   ghInput("COMMAND"),
		ActionRef: ghInput("ACTION_REF"),
		Step:      ghInput("STEP"),

		// Binary
		Version:         ghInput("VERSION"),
		CilockBinaryURL: ghInput("CILOCK_BINARY_URL"),

		// Attestation
		OutFile:    ghInput("OUTFILE"),
		WorkingDir: ghInput("WORKINGDIR"),
		Trace:      ghInputBool("TRACE"),

		// Archivista
		EnableArchivista: ghInputBoolDefault("ENABLE_ARCHIVISTA", true),
		ArchivistaServer: ghInputDefault("ARCHIVISTA_SERVER", DefaultArchivistaServer),

		// Sigstore
		EnableSigstore:     ghInputBoolDefault("ENABLE_SIGSTORE", true),
		FulcioURL:          ghInputDefault("FULCIO_URL", DefaultFulcioURL),
		FulcioOIDCClientID: ghInputDefault("FULCIO_OIDC_CLIENT_ID", DefaultFulcioOIDCClientID),
		FulcioOIDCIssuer:   ghInputDefault("FULCIO_OIDC_ISSUER", DefaultFulcioOIDCIssuer),

		// File signer
		KeyPath:         ghInput("KEY"),
		CertificatePath: ghInput("CERTIFICATE"),

		// KMS
		KMSRef:          ghInput("KMS_REF"),
		KMSAWSProfile:   ghInput("KMS_AWS_PROFILE"),
		KMSGCPCredsFile: ghInput("KMS_GCP_CREDENTIALS_FILE"),

		// Vault
		VaultURL:   ghInput("VAULT_URL"),
		VaultToken: ghInput("VAULT_TOKEN"),

		// Environment filtering
		EnvFilterSensitiveVars: ghInputBool("ENV_FILTER_SENSITIVE_VARS"),

		// Product/Material
		ProductIncludeGlob: ghInputDefault("PRODUCT_INCLUDE_GLOB", DefaultProductIncludeGlob),
		ProductExcludeGlob: ghInput("PRODUCT_EXCLUDE_GLOB"),

		// Attestor exports
		AttestorSBOMExport: ghInputBool("ATTESTOR_SBOM_EXPORT"),
		AttestorSLSAExport: ghInputBool("ATTESTOR_SLSA_EXPORT"),

		// Builder
		BuilderManifest: ghInput("BUILDER_MANIFEST"),
		BuilderPreset:   ghInput("BUILDER_PRESET"),
	}

	// Attestations — space-separated list
	attestStr := ghInputDefault("ATTESTATIONS", DefaultAttestations)
	if attestStr != "" {
		c.Attestations = strings.Fields(attestStr)
	}

	// Hashes — space-separated
	hashStr := ghInputDefault("HASHES", DefaultHashes)
	if hashStr != "" {
		c.Hashes = strings.Fields(hashStr)
	}

	// Timestamp servers — space-separated
	tsStr := ghInputDefault("TIMESTAMP_SERVERS", DefaultTimestampServer)
	if tsStr != "" {
		c.TimestampServers = strings.Fields(tsStr)
	}

	// Intermediates — comma-separated
	if v := ghInput("INTERMEDIATES"); v != "" {
		c.IntermediatePaths = strings.Split(v, ",")
	}

	// cilock-args — space-separated additional raw args
	if v := ghInput("CILOCK_ARGS"); v != "" {
		c.CilockArgs = strings.Fields(v)
	}

	// env-add-sensitive-key — comma-separated
	if v := ghInput("ENV_ADD_SENSITIVE_KEY"); v != "" {
		c.EnvAddSensitiveKey = strings.Split(v, ",")
	}

	// Archivista headers — auto-inject TESTIFYSEC_API_KEY if set
	if apiKey := os.Getenv("TESTIFYSEC_API_KEY"); apiKey != "" {
		c.ArchivistaHeaders = append(c.ArchivistaHeaders, fmt.Sprintf("Authorization: Token %s", apiKey))
	}

	// Action inputs — JSON or YAML map
	if v := ghInput("ACTION_INPUTS"); v != "" {
		m, err := parseActionInputs(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse action-inputs: %w", err)
		}
		c.ActionInputs = m
	}

	// Action env — KEY=VALUE per line
	if v := ghInput("ACTION_ENV"); v != "" {
		c.ActionEnv = parseKeyValueLines(v)
	}

	return c, nil
}

// ghInput reads a GitHub Actions input from INPUT_<NAME>.
func ghInput(name string) string {
	return strings.TrimSpace(os.Getenv("INPUT_" + name))
}

// ghInputDefault reads a GitHub Actions input with a default value.
func ghInputDefault(name, defaultVal string) string {
	if v := ghInput(name); v != "" {
		return v
	}
	return defaultVal
}

// ghInputBool reads a GitHub Actions input as a boolean (true/false string).
func ghInputBool(name string) bool {
	return strings.EqualFold(ghInput(name), "true")
}

// ghInputBoolDefault reads a GitHub Actions input as a boolean with a default.
func ghInputBoolDefault(name string, defaultVal bool) bool {
	v := ghInput(name)
	if v == "" {
		return defaultVal
	}
	return strings.EqualFold(v, "true")
}

// parseActionInputs parses a JSON map of action inputs.
func parseActionInputs(s string) (map[string]string, error) {
	m := make(map[string]string)
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseKeyValueLines parses KEY=VALUE pairs separated by newlines.
func parseKeyValueLines(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

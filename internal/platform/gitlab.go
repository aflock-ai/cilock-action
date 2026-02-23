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
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/cilock-action/internal/config"
)

// ParseGitLab populates a Config from GitLab CI CILOCK_* environment variables.
func ParseGitLab() (*config.Config, error) {
	c := &config.Config{
		// Core
		Command:   glEnv("COMMAND"),
		ActionRef: glEnv("ACTION_REF"),
		Step:      glEnv("STEP"),

		// Attestation
		OutFile:    glEnv("OUTFILE"),
		WorkingDir: glEnv("WORKINGDIR"),
		Trace:      glEnvBool("TRACE"),

		// Archivista
		EnableArchivista: glEnvBoolDefault("ENABLE_ARCHIVISTA", true),
		ArchivistaServer: glEnvDefault("ARCHIVISTA_SERVER", DefaultArchivistaServer),

		// Sigstore
		EnableSigstore:     glEnvBoolDefault("ENABLE_SIGSTORE", false), // GitLab doesn't have native OIDC for sigstore by default
		FulcioURL:          glEnvDefault("FULCIO_URL", DefaultFulcioURL),
		FulcioOIDCClientID: glEnvDefault("FULCIO_OIDC_CLIENT_ID", DefaultFulcioOIDCClientID),
		FulcioOIDCIssuer:   glEnv("FULCIO_OIDC_ISSUER"),
		FulcioToken:        glEnv("FULCIO_TOKEN"),

		// File signer
		KeyPath:         glEnv("KEY"),
		CertificatePath: glEnv("CERTIFICATE"),

		// KMS
		KMSRef:          glEnv("KMS_REF"),
		KMSAWSProfile:   glEnv("KMS_AWS_PROFILE"),
		KMSGCPCredsFile: glEnv("KMS_GCP_CREDENTIALS_FILE"),

		// Vault
		VaultURL:   glEnv("VAULT_URL"),
		VaultToken: glEnv("VAULT_TOKEN"),

		// Environment filtering
		EnvFilterSensitiveVars: glEnvBool("ENV_FILTER_SENSITIVE_VARS"),

		// Product/Material
		ProductIncludeGlob: glEnvDefault("PRODUCT_INCLUDE_GLOB", DefaultProductIncludeGlob),
		ProductExcludeGlob: glEnv("PRODUCT_EXCLUDE_GLOB"),
	}

	// Attestations
	attestStr := glEnvDefault("ATTESTATIONS", "environment git gitlab")
	if attestStr != "" {
		c.Attestations = strings.Fields(attestStr)
	}

	// Hashes
	hashStr := glEnvDefault("HASHES", DefaultHashes)
	if hashStr != "" {
		c.Hashes = strings.Fields(hashStr)
	}

	// Timestamp servers
	tsStr := glEnvDefault("TIMESTAMP_SERVERS", DefaultTimestampServer)
	if tsStr != "" {
		c.TimestampServers = strings.Fields(tsStr)
	}

	// Intermediates
	if v := glEnv("INTERMEDIATES"); v != "" {
		c.IntermediatePaths = strings.Split(v, ",")
	}

	// Additional args
	if v := glEnv("ARGS"); v != "" {
		c.CilockArgs = strings.Fields(v)
	}

	// Sensitive keys
	if v := glEnv("ENV_ADD_SENSITIVE_KEY"); v != "" {
		c.EnvAddSensitiveKey = strings.Split(v, ",")
	}

	// API key auto-injection
	if apiKey := os.Getenv("TESTIFYSEC_API_KEY"); apiKey != "" {
		c.ArchivistaHeaders = append(c.ArchivistaHeaders, fmt.Sprintf("Authorization: Token %s", apiKey))
	}

	return c, nil
}

func glEnv(name string) string {
	return strings.TrimSpace(os.Getenv("CILOCK_" + name))
}

func glEnvDefault(name, defaultVal string) string {
	if v := glEnv(name); v != "" {
		return v
	}
	return defaultVal
}

func glEnvBool(name string) bool {
	return strings.EqualFold(glEnv(name), "true")
}

func glEnvBoolDefault(name string, defaultVal bool) bool {
	v := glEnv(name)
	if v == "" {
		return defaultVal
	}
	return strings.EqualFold(v, "true")
}

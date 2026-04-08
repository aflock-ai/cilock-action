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

// Package config defines the platform-agnostic configuration for cilock-action.
package config

// Config holds the complete, platform-agnostic configuration for a cilock-action run.
// It is populated by a platform-specific parser (GitHub, GitLab, or CLI).
type Config struct {
	// Core — one of Command or ActionRef is required
	Command   string
	ActionRef string
	Step      string

	// Action wrapping
	ActionInputs map[string]string // Inputs to pass to the wrapped action
	ActionEnv    map[string]string // Additional env vars for the wrapped action

	// Binary
	Version         string
	CilockBinaryURL string
	CilockArgs      []string

	// Attestation
	Attestations []string
	OutFile      string
	WorkingDir   string
	Trace        bool
	Hashes       []string

	// Archivista
	EnableArchivista  bool
	ArchivistaServer  string
	ArchivistaHeaders []string

	// Archivista OIDC auth — send GitHub Actions OIDC token as Bearer token
	ArchivistaOIDC     bool   // Enable OIDC auth for Archivista uploads
	ArchivistaAudience string // OIDC audience for the Archivista token (default: archivista server URL)

	// Sigstore / Fulcio
	EnableSigstore     bool
	FulcioURL          string
	FulcioOIDCClientID string
	FulcioOIDCIssuer   string
	FulcioToken        string
	FulcioUseHTTP      bool

	// File signer
	KeyPath           string
	CertificatePath   string
	IntermediatePaths []string

	// KMS
	KMSRef          string
	KMSAWSProfile   string
	KMSGCPCredsFile string

	// Vault
	VaultURL   string
	VaultToken string

	// Timestamps
	TimestampServers []string

	// Environment filtering
	EnvAddSensitiveKey     []string
	EnvFilterSensitiveVars bool

	// Product/Material globs
	ProductIncludeGlob string
	ProductExcludeGlob string

	// Attestor exports
	AttestorSBOMExport bool
	AttestorSLSAExport bool

	// Builder
	BuilderManifest string
	BuilderPreset   string
}

// Validate checks that the configuration is minimally valid.
func (c *Config) Validate() error {
	if c.Command == "" && c.ActionRef == "" {
		return ErrNoCommandOrAction
	}
	if c.Command != "" && c.ActionRef != "" {
		return ErrBothCommandAndAction
	}
	if c.Step == "" {
		return ErrNoStep
	}
	return nil
}

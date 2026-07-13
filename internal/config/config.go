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

import "github.com/aflock-ai/rookery/platformauth"

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
	// Subjects holds raw --subjects values to forward to the cilock binary.
	// Each entry is either a bare name (e.g. "product:<uuid>") or a
	// "name=<alg>:<hex>" pair with an explicit digest. See cilock's
	// parseSubjectFlags for the full grammar.
	Subjects []string

	// Archivista
	EnableArchivista  bool
	ArchivistaServer  string
	ArchivistaHeaders []string

	// Archivista OIDC auth — send GitHub Actions OIDC token as Bearer token
	ArchivistaOIDC     bool   // Enable OIDC auth for Archivista uploads
	ArchivistaAudience string // OIDC audience for the Archivista token (default: archivista server URL)

	// TestifySec platform binding
	PlatformURL string // TestifySec platform URL — source for the login audience + endpoints
	// Product is an optional product UUID selector. Required only for the
	// ambiguous case (a repository mapped to multiple products); the binding
	// failure message tells the user when it is needed.
	Product string
	// PlatformBindingSkip opts a platform-authenticated run out of the
	// fail-closed product-binding gate (an org-level attestation not tied to a
	// product). Fail-closed by default.
	PlatformBindingSkip bool
	// PlatformBinding is the tenant/product resolved at run-entry by
	// ResolvePlatformBinding, threaded to the platform attestor. Nil when not
	// resolved (not authenticated / opted out / endpoint unavailable).
	PlatformBinding *platformauth.Binding

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

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

// Package attestation wraps rookery's workflow API to run attestation
// from cilock-action's config.
package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/aflock-ai/rookery/plugins/signers/file"
	"github.com/aflock-ai/rookery/plugins/signers/fulcio"

	"github.com/aflock-ai/cilock-action/internal/config"
)

// Result holds the output of an attestation run.
type Result struct {
	GitOIDs          []string
	AttestationFiles []string
}

// Run executes a command wrapped with rookery attestation.
func Run(ctx context.Context, cfg *config.Config, command []string) (*Result, error) {
	signers, err := buildSigners(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build signers: %w", err)
	}

	timestampers := buildTimestampers(cfg)

	attestors, err := buildAttestors(cfg, command)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestors: %w", err)
	}

	attestationOpts, err := buildAttestationOpts(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestation options: %w", err)
	}

	runOpts := []workflow.RunOption{
		workflow.RunWithAttestors(attestors),
		workflow.RunWithAttestationOpts(attestationOpts...),
		workflow.RunWithTimestampers(timestampers...),
	}

	if len(signers) > 0 {
		runOpts = append(runOpts, workflow.RunWithSigners(signers...))
	} else {
		runOpts = append(runOpts, workflow.RunWithInsecure(true))
	}

	results, err := workflow.RunWithExports(cfg.Step, runOpts...)
	if err != nil {
		return nil, fmt.Errorf("attestation run failed: %w", err)
	}

	return processResults(ctx, cfg, results)
}

func buildSigners(ctx context.Context, cfg *config.Config) ([]cryptoutil.Signer, error) {
	var signers []cryptoutil.Signer

	// Fulcio/Sigstore signer
	if cfg.EnableSigstore {
		opts := []fulcio.Option{}
		if cfg.FulcioURL != "" {
			opts = append(opts, fulcio.WithFulcioURL(cfg.FulcioURL))
		}
		if cfg.FulcioOIDCIssuer != "" {
			opts = append(opts, fulcio.WithOidcIssuer(cfg.FulcioOIDCIssuer))
		}
		if cfg.FulcioOIDCClientID != "" {
			opts = append(opts, fulcio.WithOidcClientID(cfg.FulcioOIDCClientID))
		}
		if cfg.FulcioToken != "" {
			opts = append(opts, fulcio.WithToken(cfg.FulcioToken))
		}

		fsp := fulcio.New(opts...)
		s, err := fsp.Signer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create fulcio signer: %w", err)
		}
		signers = append(signers, s)
	}

	// File signer
	if cfg.KeyPath != "" {
		opts := []file.Option{
			file.WithKeyPath(cfg.KeyPath),
		}
		if cfg.CertificatePath != "" {
			opts = append(opts, file.WithCertPath(cfg.CertificatePath))
		}
		if len(cfg.IntermediatePaths) > 0 {
			opts = append(opts, file.WithIntermediatePaths(cfg.IntermediatePaths))
		}

		fsp := file.New(opts...)
		s, err := fsp.Signer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create file signer: %w", err)
		}
		signers = append(signers, s)
	}

	return signers, nil
}

func buildTimestampers(cfg *config.Config) []timestamp.Timestamper {
	var ts []timestamp.Timestamper
	for _, url := range cfg.TimestampServers {
		ts = append(ts, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}
	return ts
}

func buildAttestors(cfg *config.Config, command []string) ([]attestation.Attestor, error) {
	attestors := []attestation.Attestor{product.New(), material.New()}

	if len(command) > 0 {
		attestors = append(attestors, commandrun.New(
			commandrun.WithCommand(command),
			commandrun.WithTracing(cfg.Trace),
		))
	}

	for _, name := range cfg.Attestations {
		if name == "command-run" || name == "material" || name == "product" {
			continue
		}
		a, err := attestation.GetAttestor(name)
		if err != nil {
			return nil, fmt.Errorf("unknown attestor %q: %w", name, err)
		}
		attestors = append(attestors, a)
	}

	return attestors, nil
}

func buildAttestationOpts(cfg *config.Config) ([]attestation.AttestationContextOption, error) {
	var opts []attestation.AttestationContextOption

	if cfg.WorkingDir != "" {
		opts = append(opts, attestation.WithWorkingDir(cfg.WorkingDir))
	}

	if len(cfg.Hashes) > 0 {
		var hashes []cryptoutil.DigestValue
		for _, h := range cfg.Hashes {
			hash, err := cryptoutil.HashFromString(h)
			if err != nil {
				return nil, fmt.Errorf("invalid hash algorithm %q: %w", h, err)
			}
			hashes = append(hashes, cryptoutil.DigestValue{Hash: hash, GitOID: false})
		}
		opts = append(opts, attestation.WithHashes(hashes))
	}

	if cfg.EnvFilterSensitiveVars {
		opts = append(opts, attestation.WithEnvFilterVarsEnabled())
	}

	if len(cfg.EnvAddSensitiveKey) > 0 {
		opts = append(opts, attestation.WithEnvAdditionalKeys(cfg.EnvAddSensitiveKey))
	}

	return opts, nil
}

func processResults(ctx context.Context, cfg *config.Config, results []workflow.RunResult) (*Result, error) {
	result := &Result{}

	for _, r := range results {
		envelope := r.SignedEnvelope

		// In insecure mode (no signers), the workflow returns a zero-value envelope.
		// Construct a proper unsigned DSSE envelope from the collection.
		if envelope.PayloadType == "" && r.Collection.Name != "" {
			var err error
			envelope, err = buildUnsignedEnvelope(r.Collection)
			if err != nil {
				return nil, fmt.Errorf("failed to build unsigned envelope: %w", err)
			}
		}

		signedBytes, err := json.Marshal(&envelope)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal envelope: %w", err)
		}

		outfile := cfg.OutFile
		if r.AttestorName != "" {
			safeName := strings.ReplaceAll(r.AttestorName, "/", "-")
			outfile += "-" + safeName + ".json"
		}

		if outfile != "" {
			if err := os.WriteFile(outfile, signedBytes, 0o644); err != nil {
				return nil, fmt.Errorf("failed to write attestation to %s: %w", outfile, err)
			}
			result.AttestationFiles = append(result.AttestationFiles, outfile)
			log.Infof("Wrote attestation to %s", outfile)
		} else {
			fmt.Println(string(signedBytes))
		}

		if cfg.EnableArchivista {
			gitoid, err := storeInArchivista(ctx, cfg, r)
			if err != nil {
				return nil, err
			}
			if gitoid != "" {
				result.GitOIDs = append(result.GitOIDs, gitoid)
				log.Infof("Stored in archivista as %s", gitoid)
			}
		}
	}

	return result, nil
}

func buildUnsignedEnvelope(collection attestation.Collection) (dsse.Envelope, error) {
	predicateJSON, err := json.Marshal(&collection)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal collection: %w", err)
	}

	stmt, err := intoto.NewStatement(attestation.CollectionType, predicateJSON, collection.Subjects())
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to create statement: %w", err)
	}

	stmtJSON, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal statement: %w", err)
	}

	return dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     stmtJSON,
		Signatures:  []dsse.Signature{},
	}, nil
}

func storeInArchivista(ctx context.Context, cfg *config.Config, r workflow.RunResult) (string, error) {
	headers := http.Header{}
	for _, h := range cfg.ArchivistaHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid archivista header: %s", h)
		}
		headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	var opts []archivista.Option
	if len(headers) > 0 {
		opts = append(opts, archivista.WithHeaders(headers))
	}

	client := archivista.New(cfg.ArchivistaServer, opts...)
	gitoid, err := client.Store(ctx, r.SignedEnvelope)
	if err != nil {
		return "", fmt.Errorf("failed to store in archivista: %w", err)
	}

	return gitoid, nil
}

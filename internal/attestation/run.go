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
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/githubaction"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/aflock-ai/rookery/plugins/attestors/secretscan"
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

// ActionConfig holds metadata about the action being executed, used to
// configure the github-action attestor.
type ActionConfig struct {
	Ref       string
	Type      string
	Name      string
	Dir       string
	Inputs    map[string]string
	RefPinned bool // true if the ref is a full commit SHA (40 hex chars)
	// DockerConfigFn is called after action execution to retrieve Docker container
	// configuration for attestation recording. May be nil for non-Docker actions.
	DockerConfigFn func() *githubaction.DockerContainerConfig
}

// RunAction executes an action function within an attestation context using
// the github-action attestor instead of commandrun. The actionFn is called
// during the execute phase and should return the exit code.
func RunAction(ctx context.Context, cfg *config.Config, actionCfg *ActionConfig, actionFn func(ctx context.Context) (int, error)) (*Result, error) {
	signers, err := buildSigners(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build signers: %w", err)
	}

	timestampers := buildTimestampers(cfg)

	// Build action-specific attestors: material + githubaction + product (no commandrun).
	// The githubaction attestor runs during the Execute phase (between material and product),
	// executing the action via WithExecuteFunc and capturing exit code + metadata.
	dockerConfigFn := actionCfg.DockerConfigFn

	gaAttestor := githubaction.New(
		githubaction.WithActionRef(actionCfg.Ref),
		githubaction.WithActionType(actionCfg.Type),
		githubaction.WithActionName(actionCfg.Name),
		githubaction.WithActionDir(actionCfg.Dir),
		githubaction.WithActionInputs(actionCfg.Inputs),
		githubaction.WithRefPinned(actionCfg.RefPinned),
	)

	// Wrap the execute function to capture Docker config after execution.
	// The attestor's Docker field is set directly via the captured pointer.
	gaAttestor.SetExecuteFunc(func(ctx context.Context) (int, error) {
		code, err := actionFn(ctx)
		if dockerConfigFn != nil {
			if dcfg := dockerConfigFn(); dcfg != nil {
				gaAttestor.Docker = dcfg
			}
		}
		return code, err
	})

	attestors := []attestation.Attestor{material.New(), gaAttestor, product.New()}

	secretscanOpts := parseCilockArgs(cfg.CilockArgs)

	// Add any additional attestors from config (but skip commandrun/material/product/github-action)
	for _, name := range cfg.Attestations {
		switch name {
		case "command-run", "material", "product", "github-action":
			continue
		}
		a, err := buildNamedAttestor(name, secretscanOpts)
		if err != nil {
			return nil, err
		}
		attestors = append(attestors, a)
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
		if cfg.FulcioUseHTTP {
			opts = append(opts, fulcio.WithUseHTTP(true))
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

// warnIfNoProducts emits a GitHub Actions warning when the build
// produced zero products. Without this, builds that write outside the
// workspace (e.g., to /tmp) or use a product glob that matches nothing
// silently produce an empty attestation — the operator only notices
// downstream when verifying.
//
// The warning surfaces the active glob and tells the user exactly
// where to override it.
func warnIfNoProducts(cfg *config.Config, results []workflow.RunResult) {
	count := 0
	for _, r := range results {
		for _, ca := range r.Collection.Attestations {
			if p, ok := ca.Attestation.(attestation.Producer); ok {
				count += len(p.Products())
			}
		}
	}
	if count > 0 {
		return
	}

	glob := resolveProductIncludeGlob(cfg)
	src := "default (workingDir/**)"
	switch {
	case len(cfg.Products) > 0:
		src = fmt.Sprintf("`products` input (%d entr%s)", len(cfg.Products), pluralY(len(cfg.Products)))
	case cfg.ProductIncludeGlob != "":
		src = "legacy `product-include-glob` input"
	}
	fmt.Fprintf(os.Stderr,
		"::warning::cilock-action: no products detected. Active glob: %q (from %s). "+
			"Set the `products` input on the action to one or more paths/globs "+
			"matching your build's output, e.g.:\n"+
			"    - uses: aflock-ai/cilock-action@v1\n"+
			"      with:\n"+
			"        products: |\n"+
			"          bin/myapp\n"+
			"          dist/**\n",
		glob, src)
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// resolveProductIncludeGlob picks the product glob the operator
// intended. Priority:
//  1. cfg.Products (newline-separated list of paths/globs) → wrap in
//     a brace pattern so multiple entries match.
//  2. legacy cfg.ProductIncludeGlob single string.
//  3. default: workingDir/** so anything written inside the workspace
//     counts as a product. Cache dirs (.cache, .gradle, etc.) are
//     filtered out separately by the rookery cache-pattern matcher.
//
// The previous default of "*" matched every file written anywhere,
// turning every compiler intermediate into a "product". gh CLI smoke
// produced 9281 products under that rule.
func resolveProductIncludeGlob(cfg *config.Config) string {
	if len(cfg.Products) > 0 {
		if len(cfg.Products) == 1 {
			return cfg.Products[0]
		}
		// gobwas/glob (rookery's product attestor) supports
		// {a,b,c} brace patterns.
		return "{" + strings.Join(cfg.Products, ",") + "}"
	}
	if cfg.ProductIncludeGlob != "" {
		return cfg.ProductIncludeGlob
	}
	if cfg.WorkingDir != "" {
		return strings.TrimRight(cfg.WorkingDir, "/") + "/**"
	}
	return "**"
}

func buildAttestors(cfg *config.Config, command []string) ([]attestation.Attestor, error) {
	// Resolve the products glob. Priority: explicit Products list >
	// legacy ProductIncludeGlob > default (workingDir/**).
	//
	// Without this, every file the build writes — compiler temps,
	// link intermediates, cache artifacts — gets tagged as a product
	// (gh CLI build produced 9281 "products" with the prior default
	// of "*"). The right model: products are the deliverable; default
	// scope is whatever the build writes inside its workspace.
	productIncludeGlob := resolveProductIncludeGlob(cfg)

	attestors := []attestation.Attestor{
		product.New(product.WithIncludeGlob(productIncludeGlob)),
		material.New(),
	}
	if cfg.ProductExcludeGlob != "" {
		// Replace the products attestor with one that has both globs.
		attestors[0] = product.New(
			product.WithIncludeGlob(productIncludeGlob),
			product.WithExcludeGlob(cfg.ProductExcludeGlob),
		)
	}

	if len(command) > 0 {
		attestors = append(attestors, commandrun.New(
			commandrun.WithCommand(command),
			commandrun.WithTracing(cfg.Trace),
		))
	}

	secretscanOpts := parseCilockArgs(cfg.CilockArgs)

	for _, name := range cfg.Attestations {
		if name == "command-run" || name == "material" || name == "product" {
			continue
		}
		a, err := buildNamedAttestor(name, secretscanOpts)
		if err != nil {
			return nil, err
		}
		attestors = append(attestors, a)
	}

	return attestors, nil
}

// buildNamedAttestor looks up an attestor by name. For attestors whose
// configuration is exposed via the `cilock-args` input (currently
// secretscan), it constructs the attestor directly with the parsed
// options instead of taking the default-configured copy from the
// registry — which is the only way to honor flags like
// `--attestor-secretscan-fail-on-detection` in-process, since
// cilock-action runs rookery as a library and never shells out to cilock.
func buildNamedAttestor(name string, secretscanOpts []secretscan.Option) (attestation.Attestor, error) {
	if name == "secretscan" {
		return secretscan.New(secretscanOpts...), nil
	}
	a, err := attestation.GetAttestor(name)
	if err != nil {
		return nil, fmt.Errorf("unknown attestor %q: %w", name, err)
	}
	return a, nil
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

	// Inspect the product attestor's output count BEFORE serialising
	// so we can give the user actionable feedback when their products
	// list (or default workingDir glob) matched nothing.
	warnIfNoProducts(cfg, results)

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

		outfile := applyAttestorSuffix(cfg.OutFile, r.AttestorName)

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

// applyAttestorSuffix appends an attestor name suffix to an outfile path.
// e.g. ("/tmp/att.json", "parent/child") → "/tmp/att-parent-child.json"
func applyAttestorSuffix(outfile, attestorName string) string {
	if attestorName == "" {
		return outfile
	}
	safeName := strings.ReplaceAll(attestorName, "/", "-")
	ext := filepath.Ext(outfile)
	base := strings.TrimSuffix(outfile, ext)
	result := base + "-" + safeName + ext
	if ext == "" {
		result += ".json"
	}
	return result
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

	// OIDC auth: fetch a GitHub Actions OIDC token for Archivista uploads.
	// This reuses the same OIDC identity that Fulcio uses for signing certs,
	// but with a different audience so the token is scoped to Archivista.
	if cfg.ArchivistaOIDC && os.Getenv("GITHUB_ACTIONS") == "true" {
		token, err := fetchGitHubOIDCToken(cfg.ArchivistaAudience)
		if err != nil {
			return "", fmt.Errorf("failed to fetch OIDC token for archivista: %w", err)
		}
		headers.Set("Authorization", "Bearer "+token)
		log.Infof("Using GitHub Actions OIDC token for Archivista upload (audience: %s)", cfg.ArchivistaAudience)
	} else {
		log.Infof("Archivista auth: OIDC not active, headers count=%d", len(cfg.ArchivistaHeaders))
	}

	// Static headers (legacy API keys or custom headers)
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

// fetchGitHubOIDCToken requests an OIDC token from GitHub Actions with the
// given audience. This is the same mechanism Fulcio uses to get signing certs —
// we reuse it for Archivista upload auth with a different audience.
func fetchGitHubOIDCToken(audience string) (string, error) {
	tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if tokenURL == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL not set — not in GitHub Actions?")
	}
	bearerToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if bearerToken == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")
	}

	u, err := url.Parse(tokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse token URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+bearerToken)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("OIDC token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode OIDC token response: %w", err)
	}
	if tokenResp.Value == "" {
		return "", fmt.Errorf("empty OIDC token in response")
	}

	return tokenResp.Value, nil
}

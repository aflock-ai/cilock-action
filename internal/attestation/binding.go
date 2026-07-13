// Copyright 2026 The Aflock Authors
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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/platformauth"

	"github.com/aflock-ai/cilock-action/internal/config"
)

// bindingMintTokenFn / bindingResolveFn are package vars so the fail-closed
// product-binding gate can be unit-tested without a real GitHub Actions OIDC
// endpoint or platform.
var (
	bindingMintTokenFn = fetchGitHubOIDCToken
	bindingResolveFn   = platformauth.ResolveBinding
)

// ResolvePlatformBinding is the client-side fail-closed product-binding gate for
// cilock-action. It runs at run START (before the wrapped command/action
// executes) so an ambiguous or unconnected repository fails BEFORE an
// un-linkable build runs.
//
// Rule:
//   - platform-binding: skip → proceed (explicit opt-out).
//   - not platform-authenticated (no ambient GitHub Actions OIDC, or no platform
//     integration) → proceed; the platform attestor soft-skips.
//   - authenticated + repo resolves to exactly ONE product → proceed; the
//     resolved binding is set on cfg for the platform attestor.
//   - authenticated + repo maps to ZERO / AMBIGUOUS from a REACHABLE endpoint →
//     HARD FAIL with a machine-actionable message.
//   - endpoint unreachable / not deployed yet / 5xx / auth rejected → loud
//     SOFT-skip (WARN), so a client that ships ahead of the server's deploy
//     never breaks the build (evidence just won't auto-link).
//
// On success it sets cfg.PlatformBinding. The minted login-audience OIDC token
// is used only for the exchange and is never logged or persisted.
func ResolvePlatformBinding(cfg *config.Config) error {
	if cfg.PlatformBindingSkip {
		log.Infof("platform-binding: skip — proceeding without a product binding")
		return nil
	}
	if cfg.PlatformURL == "" {
		return nil // no platform integration
	}
	// Platform authentication in CI is the ambient GitHub Actions OIDC identity
	// (id-token: write) that also authenticates the Archivista upload.
	if !cfg.ArchivistaOIDC || os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") == "" || os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") == "" {
		return nil
	}

	loginAudience := strings.TrimRight(cfg.PlatformURL, "/") + "/login"
	token, err := bindingMintTokenFn(loginAudience)
	if err != nil {
		log.Warnf("product binding skipped: could not mint a login-audience OIDC token: %v", err)
		return nil
	}

	binding, err := bindingResolveFn(cfg.PlatformURL, token, cfg.Product)
	if err != nil {
		return classifyActionBindingError(cfg.PlatformURL, err)
	}
	cfg.PlatformBinding = &binding
	log.Infof("platform binding resolved: product %q (%s) in tenant %q (%s)",
		binding.ProductName, binding.ProductID, binding.TenantName, binding.TenantID)
	return nil
}

// classifyActionBindingError fails closed by default: it hard-fails on every
// deterministic config/auth error from a REACHABLE endpoint (repository_not_mapped,
// ambiguous_product, invalid/absent product, 401, 403, malformed response) and
// degrades to a loud soft-skip ONLY when the endpoint is genuinely unavailable
// (transport failure, 404-no-route, 5xx, non-JSON 200) — so a client that ships
// before the server's endpoint is deployed does not break the build.
func classifyActionBindingError(platformURL string, err error) error {
	var notMapped *platformauth.RepositoryNotMappedError
	if errors.As(err, &notMapped) {
		return errors.New(actionRepoNotMappedMessage(platformURL, notMapped))
	}
	var ambiguous *platformauth.AmbiguousProductError
	if errors.As(err, &ambiguous) {
		return errors.New(actionAmbiguousMessage(ambiguous))
	}
	var unavailable *platformauth.BindingUnavailableError
	if errors.As(err, &unavailable) {
		log.Warnf("platform binding endpoint unavailable (the server may not be deployed yet) — "+
			"proceeding without product binding; evidence will not auto-link to a product: %v", err)
		return nil
	}
	return fmt.Errorf("platform binding failed (authenticated, but could not resolve a product binding): %w. "+
		"Fix the configuration, or set `platform-binding: skip` to attest without a product binding", err)
}

// actionRepoNotMappedMessage names the repository (+ github_repository_id), the
// tenant, and the exact action-input remediation so an automated CI agent can
// self-correct.
func actionRepoNotMappedMessage(platformURL string, e *platformauth.RepositoryNotMappedError) string {
	repo, repoID := repoIdentifiers(e.Repository, e.RepositoryID)
	return fmt.Sprintf("platform binding failed: repository %s (github_repository_id=%s) is authenticated to "+
		"tenant %q (%s) but is not connected to any product. Fix: connect the repo to a product at %s/settings, "+
		"or pass an explicit product (action input `product: <uuid>`). To intentionally attest without a product "+
		"binding, set `platform-binding: skip`.",
		repo, repoID, e.TenantName, e.TenantID, strings.TrimRight(strings.TrimSpace(platformURL), "/"))
}

// actionAmbiguousMessage lists every candidate product UUID + name so an agent
// can choose exactly one via the `product` action input.
func actionAmbiguousMessage(e *platformauth.AmbiguousProductError) string {
	repo, _ := repoIdentifiers(e.Repository, e.RepositoryID)
	parts := make([]string, 0, len(e.Candidates))
	for _, c := range e.Candidates {
		parts = append(parts, fmt.Sprintf("%s %q", c.ProductID, c.ProductName))
	}
	return fmt.Sprintf("platform binding is ambiguous: repository %s maps to %d products in tenant %q: [%s]. "+
		"Pass exactly one: action input `product: <uuid>`.",
		repo, len(e.Candidates), e.TenantName, strings.Join(parts, ", "))
}

// repoIdentifiers prefers the endpoint-supplied repository + id, falling back to
// the ambient GitHub Actions env so the message names the repo even when the
// typed error omits it.
func repoIdentifiers(repo, repoID string) (string, string) {
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if repoID == "" {
		repoID = os.Getenv("GITHUB_REPOSITORY_ID")
	}
	if repo == "" {
		repo = "(unknown repository)"
	}
	if repoID == "" {
		repoID = "unknown"
	}
	return repo, repoID
}

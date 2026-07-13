// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package attestation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/platformauth"

	"github.com/aflock-ai/cilock-action/internal/config"
)

const (
	bTenant  = "11111111-1111-1111-1111-111111111111"
	bProduct = "22222222-2222-2222-2222-222222222222"
	bPlatURL = "https://platform.testifysec.com"
)

// enterCIAuth sets the ambient GitHub Actions OIDC signals + a stub token
// minter so the gate treats the run as platform-authenticated without a real
// OIDC endpoint.
func enterCIAuth(t *testing.T) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
	origMint := bindingMintTokenFn
	t.Cleanup(func() { bindingMintTokenFn = origMint })
	bindingMintTokenFn = func(string) (string, error) { return "login-token", nil }
}

func stubActionResolve(t *testing.T, fn func(url, bearer, selector string) (platformauth.Binding, error)) {
	t.Helper()
	orig := bindingResolveFn
	t.Cleanup(func() { bindingResolveFn = orig })
	bindingResolveFn = fn
}

func authedCfg() *config.Config {
	return &config.Config{PlatformURL: bPlatURL, ArchivistaOIDC: true}
}

func TestResolvePlatformBinding_SkipOptOut(t *testing.T) {
	enterCIAuth(t)
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		t.Fatal("resolve must not run when platform-binding: skip")
		return platformauth.Binding{}, nil
	})
	cfg := authedCfg()
	cfg.PlatformBindingSkip = true
	if err := ResolvePlatformBinding(cfg); err != nil {
		t.Fatalf("opt-out must proceed: %v", err)
	}
	if cfg.PlatformBinding != nil {
		t.Fatal("no binding expected on opt-out")
	}
}

func TestResolvePlatformBinding_NotAuthenticated(t *testing.T) {
	// No ambient OIDC env → not authenticated.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		t.Fatal("resolve must not run when unauthenticated")
		return platformauth.Binding{}, nil
	})
	cfg := authedCfg()
	if err := ResolvePlatformBinding(cfg); err != nil {
		t.Fatalf("unauthenticated run must proceed: %v", err)
	}
	if cfg.PlatformBinding != nil {
		t.Fatal("no binding expected when unauthenticated")
	}
}

func TestResolvePlatformBinding_Success(t *testing.T) {
	enterCIAuth(t)
	var gotBearer, gotSelector string
	stubActionResolve(t, func(_, bearer, selector string) (platformauth.Binding, error) {
		gotBearer, gotSelector = bearer, selector
		return platformauth.Binding{TenantID: bTenant, TenantName: "Acme", ProductID: bProduct, ProductName: "Widget"}, nil
	})
	cfg := authedCfg()
	cfg.Product = bProduct
	if err := ResolvePlatformBinding(cfg); err != nil {
		t.Fatalf("success must proceed: %v", err)
	}
	if cfg.PlatformBinding == nil || cfg.PlatformBinding.ProductID != bProduct {
		t.Fatalf("binding not set: %+v", cfg.PlatformBinding)
	}
	if gotBearer != "login-token" {
		t.Fatalf("gate must use the minted login token, got %q", gotBearer)
	}
	if gotSelector != bProduct {
		t.Fatalf("product selector %q not forwarded", gotSelector)
	}
}

func TestResolvePlatformBinding_RepoNotMapped_HardFail(t *testing.T) {
	enterCIAuth(t)
	t.Setenv("GITHUB_REPOSITORY", "acme/widget")
	t.Setenv("GITHUB_REPOSITORY_ID", "424242")
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		return platformauth.Binding{}, &platformauth.RepositoryNotMappedError{TenantID: bTenant, TenantName: "Acme"}
	})
	cfg := authedCfg()
	err := ResolvePlatformBinding(cfg)
	if err == nil {
		t.Fatal("repository_not_mapped must hard-fail before the build runs")
	}
	msg := err.Error()
	for _, want := range []string{"acme/widget", "424242", "Acme", bTenant, "product: <uuid>", "platform-binding: skip"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q: %q", want, msg)
		}
	}
	if cfg.PlatformBinding != nil {
		t.Fatal("no binding on failure")
	}
}

func TestResolvePlatformBinding_Ambiguous_HardFail(t *testing.T) {
	enterCIAuth(t)
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		return platformauth.Binding{}, &platformauth.AmbiguousProductError{
			TenantID: bTenant, TenantName: "Acme", Repository: "acme/monorepo",
			Candidates: []platformauth.ProductCandidate{
				{ProductID: bProduct, ProductName: "A"},
				{ProductID: "33333333-3333-3333-3333-333333333333", ProductName: "B"},
			},
		}
	})
	cfg := authedCfg()
	err := ResolvePlatformBinding(cfg)
	if err == nil {
		t.Fatal("ambiguous_product must hard-fail")
	}
	msg := err.Error()
	for _, want := range []string{"acme/monorepo", bProduct, "33333333-3333-3333-3333-333333333333", "product: <uuid>"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q: %q", want, msg)
		}
	}
}

// TestResolvePlatformBinding_EndpointUnreachable_SoftSkip covers the merge-window
// case: the client can ship before the server's /api/auth/resolve-binding is
// deployed. A transport/availability failure must NOT break the build.
func TestResolvePlatformBinding_EndpointUnreachable_SoftSkip(t *testing.T) {
	enterCIAuth(t)
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		// The only soft-skippable class: a genuinely-unavailable endpoint.
		// ResolveBinding returns this typed error for a transport failure /
		// 404-no-typed-body / 5xx / non-JSON 200; the stub must too.
		return platformauth.Binding{}, &platformauth.BindingUnavailableError{
			Reason: fmt.Sprintf("resolve-binding: %s/api/auth/resolve-binding returned 404 (endpoint unavailable / not deployed)", bPlatURL),
		}
	})
	cfg := authedCfg()
	if err := ResolvePlatformBinding(cfg); err != nil {
		t.Fatalf("an unreachable/undeployed endpoint must SOFT-skip, got hard error: %v", err)
	}
	if cfg.PlatformBinding != nil {
		t.Fatal("no binding when the endpoint is unavailable")
	}
}

// TestResolvePlatformBinding_UnknownError_HardFail locks the fail-closed
// contract: an unclassified resolve error (not a typed BindingUnavailableError)
// must HARD-fail before the wrapped build runs, rather than silently proceed.
func TestResolvePlatformBinding_UnknownError_HardFail(t *testing.T) {
	enterCIAuth(t)
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		return platformauth.Binding{}, fmt.Errorf("resolve-binding: some unexpected error")
	})
	cfg := authedCfg()
	err := ResolvePlatformBinding(cfg)
	if err == nil {
		t.Fatal("an unclassified binding error must hard-fail (fail closed)")
	}
	if !strings.Contains(err.Error(), "platform-binding: skip") {
		t.Fatalf("hard-fail message must name the opt-out remediation, got %q", err.Error())
	}
	if cfg.PlatformBinding != nil {
		t.Fatal("no binding on a hard failure")
	}
}

func TestResolvePlatformBinding_MintFailure_SoftSkip(t *testing.T) {
	enterCIAuth(t)
	bindingMintTokenFn = func(string) (string, error) { return "", fmt.Errorf("no id-token: write") }
	stubActionResolve(t, func(string, string, string) (platformauth.Binding, error) {
		t.Fatal("resolve must not run when token minting fails")
		return platformauth.Binding{}, nil
	})
	cfg := authedCfg()
	if err := ResolvePlatformBinding(cfg); err != nil {
		t.Fatalf("a token-mint failure must SOFT-skip: %v", err)
	}
	if cfg.PlatformBinding != nil {
		t.Fatal("no binding when token minting fails")
	}
}

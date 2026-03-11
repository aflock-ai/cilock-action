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

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	oidcKID           = "mock-key-1"
	oidcTestEmail     = "test@example.com"
	oidcTestSubject   = "test@example.com"
	oidcBearerToken   = "mock-bearer-token"
)

// newOIDCHandler returns an HTTP handler implementing a minimal OIDC provider.
//
// Endpoints:
//   - GET /.well-known/openid-configuration → discovery document
//   - GET /keys → JWKS with the OIDC public key
//   - GET /token?audience=<aud> → signed JWT (requires Bearer auth)
func newOIDCHandler(pki *pkiBundle, port int) http.Handler {
	mux := http.NewServeMux()
	issuer := fmt.Sprintf("http://localhost:%d", port)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[OIDC] %s %s", r.Method, r.URL.Path)
		doc := map[string]interface{}{
			"issuer":                 issuer,
			"jwks_uri":              issuer + "/keys",
			"token_endpoint":        issuer + "/token",
			"response_types_supported": []string{"id_token"},
			"subject_types_supported":  []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[OIDC] %s %s", r.Method, r.URL.Path)
		jwks := buildJWKS(pki.oidcKey)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[OIDC] %s %s", r.Method, r.URL.Path)

		// Validate bearer token.
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		audience := r.URL.Query().Get("audience")
		if audience == "" {
			audience = "sigstore"
		}

		token, err := buildJWT(pki.oidcKey, issuer, audience)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to build JWT: %v", err), http.StatusInternalServerError)
			return
		}

		// GitHub Actions OIDC response format.
		resp := map[string]interface{}{
			"count": 1,
			"value": token,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})

	return mux
}

// buildJWKS creates a JWKS response containing the OIDC public key.
func buildJWKS(key *rsa.PrivateKey) map[string]interface{} {
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": oidcKID,
				"alg": "RS256",
				"use": "sig",
				"n":   base64URLEncodeBigInt(key.PublicKey.N),
				"e":   base64URLEncodeBigInt(big.NewInt(int64(key.PublicKey.E))),
			},
		},
	}
}

// buildJWT creates a signed JWT with email and subject claims.
func buildJWT(key *rsa.PrivateKey, issuer, audience string) (string, error) {
	now := time.Now()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": oidcKID,
	}

	claims := map[string]interface{}{
		"iss":   issuer,
		"sub":   oidcTestSubject,
		"email": oidcTestEmail,
		"aud":   []string{audience},
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// base64URLEncodeBigInt encodes a big.Int as base64url without padding.
func base64URLEncodeBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

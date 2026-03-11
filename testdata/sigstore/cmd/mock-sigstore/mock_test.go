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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setupTest(t *testing.T) *pkiBundle {
	t.Helper()
	pki, err := generatePKI()
	if err != nil {
		t.Fatalf("generatePKI: %v", err)
	}
	return pki
}

func TestOIDCWellKnown(t *testing.T) {
	pki := setupTest(t)
	handler := newOIDCHandler(pki, 8283)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET .well-known: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var doc map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if _, ok := doc["issuer"]; !ok {
		t.Error("missing issuer field")
	}
	if _, ok := doc["jwks_uri"]; !ok {
		t.Error("missing jwks_uri field")
	}
}

func TestOIDCKeys(t *testing.T) {
	pki := setupTest(t)
	handler := newOIDCHandler(pki, 8283)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/keys")
	if err != nil {
		t.Fatalf("GET /keys: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatal("expected non-empty keys array")
	}

	key := keys[0].(map[string]interface{})
	if key["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", key["kty"])
	}
	if key["kid"] != oidcKID {
		t.Errorf("expected kid=%s, got %v", oidcKID, key["kid"])
	}
}

func TestOIDCToken(t *testing.T) {
	pki := setupTest(t)
	handler := newOIDCHandler(pki, 8283)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Missing bearer token should fail.
	resp, err := http.Get(srv.URL + "/token?audience=sigstore")
	if err != nil {
		t.Fatalf("GET /token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer, got %d", resp.StatusCode)
	}

	// With bearer token should succeed.
	req, _ := http.NewRequest("GET", srv.URL+"/token?audience=sigstore", nil)
	req.Header.Set("Authorization", "bearer "+oidcBearerToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /token with bearer: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	token, ok := tokenResp["value"].(string)
	if !ok || token == "" {
		t.Fatal("expected non-empty token value")
	}

	// Token should be a JWT (3 dot-separated parts).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT with 3 parts, got %d", len(parts))
	}
}

func TestFulcioSigningCert(t *testing.T) {
	pki := setupTest(t)
	handler := newFulcioHandler(pki)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Generate a client key pair (like the fulcio signer would).
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	// Marshal public key to PEM using stdlib.
	pubDER, err := x509.MarshalPKIXPublicKey(&clientKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Build request matching Fulcio's HTTP API format.
	pubPEMJSON, _ := json.Marshal(string(pubPEM))
	reqBody := `{
		"credentials": {"oidcIdentityToken": "eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.fake"},
		"publicKeyRequest": {
			"publicKey": {"content": ` + string(pubPEMJSON) + `},
			"proofOfPossession": "AAAA"
		}
	}`

	resp, err := http.Post(srv.URL+"/api/v2/signingCert", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /api/v2/signingCert: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var certResp fulcioResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if certResp.SignedCertificateEmbeddedSCT == nil {
		t.Fatal("expected signedCertificateEmbeddedSct in response")
	}
	if certResp.SignedCertificateEmbeddedSCT.Chain == nil {
		t.Fatal("expected chain in response")
	}

	certs := certResp.SignedCertificateEmbeddedSCT.Chain.Certificates
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs (leaf, intermediate, root), got %d", len(certs))
	}

	// Verify the leaf cert has the client's public key.
	leafBlock, _ := pem.Decode([]byte(certs[0]))
	if leafBlock == nil {
		t.Fatal("failed to decode leaf cert PEM")
	}
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	if leafCert.IsCA {
		t.Error("leaf cert should not be CA")
	}

	// Verify the leaf cert's public key matches the client's.
	leafECDSA, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("leaf cert public key is not ECDSA")
	}
	if !leafECDSA.Equal(&clientKey.PublicKey) {
		t.Error("leaf cert public key does not match client key")
	}

	// Verify the intermediate cert is a CA.
	interBlock, _ := pem.Decode([]byte(certs[1]))
	if interBlock == nil {
		t.Fatal("failed to decode intermediate cert PEM")
	}
	interCert, err := x509.ParseCertificate(interBlock.Bytes)
	if err != nil {
		t.Fatalf("parse intermediate cert: %v", err)
	}
	if !interCert.IsCA {
		t.Error("intermediate cert should be CA")
	}

	// Verify chain: leaf signed by intermediate, intermediate signed by root.
	rootBlock, _ := pem.Decode([]byte(certs[2]))
	if rootBlock == nil {
		t.Fatal("failed to decode root cert PEM")
	}
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		t.Fatalf("leaf cert chain verification failed: %v", err)
	}
}

func TestFulcioRejectsInvalidRequests(t *testing.T) {
	pki := setupTest(t)
	handler := newFulcioHandler(pki)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{"GET not allowed", "GET", "", http.StatusMethodNotAllowed},
		{"invalid JSON", "POST", "{invalid", http.StatusBadRequest},
		{"missing public key", "POST", `{"credentials":{}, "publicKeyRequest":{"publicKey":{"content":""}}}`, http.StatusBadRequest},
		{"invalid PEM", "POST", `{"credentials":{}, "publicKeyRequest":{"publicKey":{"content":"not-pem"}}}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			var err error
			if tt.method == "GET" {
				resp, err = http.Get(srv.URL + "/api/v2/signingCert")
			} else {
				resp, err = http.Post(srv.URL+"/api/v2/signingCert", "application/json", strings.NewReader(tt.body))
			}
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected %d, got %d", tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

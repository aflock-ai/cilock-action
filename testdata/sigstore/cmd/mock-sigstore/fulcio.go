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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

// newFulcioHandler returns an HTTP handler implementing the Fulcio v2 signing
// certificate API. It accepts POST /api/v2/signingCert requests and returns
// a certificate chain (leaf + intermediate + root) as protobuf-compatible JSON.
func newFulcioHandler(pki *pkiBundle) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v2/signingCert", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[Fulcio] %s %s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		// Parse request to extract the public key.
		var req fulcioRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		pubKeyPEM := req.PublicKeyRequest.PublicKey.Content
		if pubKeyPEM == "" {
			http.Error(w, "missing public key", http.StatusBadRequest)
			return
		}

		// Parse the public key from PEM.
		block, _ := pem.Decode([]byte(pubKeyPEM))
		if block == nil {
			http.Error(w, "invalid PEM in public key", http.StatusBadRequest)
			return
		}

		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to parse public key: %v", err), http.StatusBadRequest)
			return
		}

		// Create a short-lived leaf certificate for this public key.
		now := time.Now()
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(now.UnixNano()),
			Subject: pkix.Name{
				CommonName:   "mock-fulcio-leaf",
				Organization: []string{"Mock Sigstore"},
			},
			NotBefore:             now.Add(-5 * time.Minute),
			NotAfter:              now.Add(20 * time.Minute),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			BasicConstraintsValid: true,
		}

		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, pki.interCert, pubKey, pki.interKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create leaf cert: %v", err), http.StatusInternalServerError)
			return
		}

		// Encode all certs as PEM strings.
		leafPEM := pemEncode("CERTIFICATE", leafDER)
		interPEM := pemEncode("CERTIFICATE", pki.interCert.Raw)
		rootPEM := pemEncode("CERTIFICATE", pki.rootCert.Raw)

		// Return in Fulcio protobuf-JSON format.
		resp := fulcioResponse{
			SignedCertificateEmbeddedSCT: &fulcioCertChain{
				Chain: &fulcioCerts{
					Certificates: []string{leafPEM, interPEM, rootPEM},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
		log.Printf("[Fulcio] Issued leaf cert serial=%d", leafTemplate.SerialNumber)
	})

	return mux
}

func pemEncode(blockType string, data []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: data,
	}))
}

// JSON structures matching Fulcio's protobuf-JSON API.

type fulcioRequest struct {
	Credentials      *fulcioCredentials      `json:"credentials"`
	PublicKeyRequest *fulcioPublicKeyRequest `json:"publicKeyRequest"`
}

type fulcioCredentials struct {
	OIDCIdentityToken string `json:"oidcIdentityToken"`
}

type fulcioPublicKeyRequest struct {
	PublicKey          *fulcioPublicKey `json:"publicKey"`
	ProofOfPossession  []byte          `json:"proofOfPossession"`
}

type fulcioPublicKey struct {
	Content string `json:"content"`
}

type fulcioResponse struct {
	SignedCertificateEmbeddedSCT *fulcioCertChain `json:"signedCertificateEmbeddedSct"`
}

type fulcioCertChain struct {
	Chain *fulcioCerts `json:"chain"`
}

type fulcioCerts struct {
	Certificates []string `json:"certificates"`
}

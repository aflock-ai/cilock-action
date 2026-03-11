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

// mock-sigstore provides mock Fulcio, TSA, and OIDC servers for integration
// testing cilock-action's sigstore signing flow without external dependencies.
//
// On startup it generates ephemeral PKI (root CA, intermediate CA, OIDC signing key)
// and starts three HTTP servers:
//
//   - Mock Fulcio  (:8281) — POST /api/v2/signingCert → issues cert chain
//   - Mock TSA     (:8282) — reserved, returns 501 for now
//   - Mock OIDC    (:8283) — GET /token, GET /keys, GET /.well-known/openid-configuration
//
// It writes the root CA certificate to ca.pem in the current directory.
package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	fulcioPort := flag.Int("fulcio-port", 8281, "Port for mock Fulcio server")
	tsaPort := flag.Int("tsa-port", 8282, "Port for mock TSA server")
	oidcPort := flag.Int("oidc-port", 8283, "Port for mock OIDC server")
	caOutPath := flag.String("ca-out", "ca.pem", "Path to write root CA certificate")
	flag.Parse()

	// Generate ephemeral PKI.
	pki, err := generatePKI()
	if err != nil {
		log.Fatalf("Failed to generate PKI: %v", err)
	}
	log.Println("Generated ephemeral PKI")

	// Write root CA cert to file for consumers.
	rootPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pki.rootCert.Raw,
	})
	if err := os.WriteFile(*caOutPath, rootPEM, 0o644); err != nil {
		log.Fatalf("Failed to write CA cert: %v", err)
	}
	log.Printf("Wrote root CA to %s", *caOutPath)

	// Start OIDC server.
	oidcHandler := newOIDCHandler(pki, *oidcPort)
	oidcServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *oidcPort),
		Handler: oidcHandler,
	}
	go func() {
		log.Printf("Mock OIDC server listening on :%d", *oidcPort)
		if err := oidcServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("OIDC server error: %v", err)
		}
	}()

	// Start Fulcio server.
	fulcioHandler := newFulcioHandler(pki)
	fulcioServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *fulcioPort),
		Handler: fulcioHandler,
	}
	go func() {
		log.Printf("Mock Fulcio server listening on :%d", *fulcioPort)
		if err := fulcioServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Fulcio server error: %v", err)
		}
	}()

	// Start TSA server (placeholder).
	tsaHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Mock TSA not yet implemented", http.StatusNotImplemented)
	})
	tsaServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *tsaPort),
		Handler: tsaHandler,
	}
	go func() {
		log.Printf("Mock TSA server listening on :%d (placeholder)", *tsaPort)
		if err := tsaServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("TSA server error: %v", err)
		}
	}()

	// Print config for consumers.
	fmt.Println("---")
	fmt.Printf("MOCK_FULCIO_URL=http://localhost:%d\n", *fulcioPort)
	fmt.Printf("MOCK_TSA_URL=http://localhost:%d\n", *tsaPort)
	fmt.Printf("MOCK_OIDC_URL=http://localhost:%d\n", *oidcPort)
	fmt.Printf("MOCK_CA_CERT=%s\n", *caOutPath)
	fmt.Println("---")

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down mock sigstore servers")
}

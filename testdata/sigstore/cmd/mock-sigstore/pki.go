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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// pkiBundle holds all the generated certificates and keys.
type pkiBundle struct {
	// CA hierarchy
	rootKey      *rsa.PrivateKey
	rootCert     *x509.Certificate
	interKey     *rsa.PrivateKey
	interCert    *x509.Certificate

	// OIDC signing key (separate from CA)
	oidcKey *rsa.PrivateKey
}

func generatePKI() (*pkiBundle, error) {
	now := time.Now()
	notAfter := now.Add(24 * time.Hour)

	// Root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Mock Sigstore Root CA",
			Organization: []string{"Mock Sigstore"},
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}

	// Intermediate CA
	interKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Mock Sigstore Intermediate CA",
			Organization: []string{"Mock Sigstore"},
		},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	interCertDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate cert: %w", err)
	}
	interCert, err := x509.ParseCertificate(interCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}

	// OIDC signing key
	oidcKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate OIDC key: %w", err)
	}

	return &pkiBundle{
		rootKey:   rootKey,
		rootCert:  rootCert,
		interKey:  interKey,
		interCert: interCert,
		oidcKey:   oidcKey,
	}, nil
}

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

package attestation

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUnsignedEnvelope_ValidCollection(t *testing.T) {
	collection := attestation.Collection{
		Name: "test-step",
	}

	env, err := buildUnsignedEnvelope(collection)
	require.NoError(t, err)

	assert.Equal(t, intoto.PayloadType, env.PayloadType)
	assert.NotEmpty(t, env.Payload)
	assert.Empty(t, env.Signatures)

	// Verify the payload round-trips through JSON correctly.
	// This simulates what processResults does: json.Marshal the envelope,
	// then consumers base64-decode the payload field from the JSON string.
	envJSON, err := json.Marshal(&env)
	require.NoError(t, err)

	// Parse the raw JSON to get the base64-encoded payload string
	var rawEnv struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	err = json.Unmarshal(envJSON, &rawEnv)
	require.NoError(t, err)

	// Base64-decode the payload (this is what consumers like node scripts do)
	payloadBytes, err := base64.StdEncoding.DecodeString(rawEnv.Payload)
	require.NoError(t, err)

	var stmt map[string]interface{}
	err = json.Unmarshal(payloadBytes, &stmt)
	require.NoError(t, err)

	assert.Equal(t, attestation.CollectionType, stmt["predicateType"])
}

func TestBuildUnsignedEnvelope_EmptyCollection(t *testing.T) {
	collection := attestation.Collection{}

	env, err := buildUnsignedEnvelope(collection)
	require.NoError(t, err)

	// Should still produce valid envelope even with empty collection
	assert.Equal(t, intoto.PayloadType, env.PayloadType)
	assert.NotEmpty(t, env.Payload)
}

func TestBuildUnsignedEnvelope_PredicateType(t *testing.T) {
	collection := attestation.Collection{
		Name: "my-step",
	}

	env, err := buildUnsignedEnvelope(collection)
	require.NoError(t, err)

	// Marshal + unmarshal to simulate what json.Marshal does in processResults
	envJSON, err := json.Marshal(&env)
	require.NoError(t, err)

	// Parse the JSON envelope
	var rawEnv struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	err = json.Unmarshal(envJSON, &rawEnv)
	require.NoError(t, err)

	// Decode the base64 payload
	stmtBytes, err := base64.StdEncoding.DecodeString(rawEnv.Payload)
	require.NoError(t, err)

	// Verify predicate contains step name
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Name string `json:"name"`
		} `json:"predicate"`
	}
	err = json.Unmarshal(stmtBytes, &stmt)
	require.NoError(t, err)

	assert.Equal(t, attestation.CollectionType, stmt.PredicateType)
	assert.Equal(t, "my-step", stmt.Predicate.Name)
}

func TestOutfileSuffix_NoExtension(t *testing.T) {
	// Simulate the outfile naming logic for export attestors
	outfile := "/tmp/attestation"
	attestorName := "parent/child"

	// Apply the naming logic
	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/attestation-parent-child.json", result)
}

func TestOutfileSuffix_WithJsonExtension(t *testing.T) {
	outfile := "/tmp/attestation.json"
	attestorName := "parent/child"

	result := applyAttestorSuffix(outfile, attestorName)
	// Should NOT produce /tmp/attestation.json-parent-child.json
	assert.Equal(t, "/tmp/attestation-parent-child.json", result)
}

func TestOutfileSuffix_EmptyAttestorName(t *testing.T) {
	outfile := "/tmp/attestation.json"
	attestorName := ""

	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/attestation.json", result)
}

func TestOutfileSuffix_NestedSlashes(t *testing.T) {
	outfile := "/tmp/out.json"
	attestorName := "a/b/c"

	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/out-a-b-c.json", result)
}

func TestOutfileSuffix_NonJsonExtension(t *testing.T) {
	outfile := "/tmp/attestation.txt"
	attestorName := "export"

	result := applyAttestorSuffix(outfile, attestorName)
	assert.Equal(t, "/tmp/attestation-export.txt", result)
}

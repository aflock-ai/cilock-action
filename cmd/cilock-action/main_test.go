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
	"testing"

	cilockattest "github.com/aflock-ai/cilock-action/internal/attestation"
	"github.com/stretchr/testify/assert"
)

func TestBuildSummary_NormalGitOID(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs:          []string{"abcdef1234567890abcdef1234567890abcdef12"},
		AttestationFiles: []string{"/tmp/attestation.json"},
	}

	summary := buildSummary(result)
	assert.Contains(t, summary, "abcdef123456...")
	assert.Contains(t, summary, "attestation.json")
}

func TestBuildSummary_ShortGitOID_NoPanic(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs: []string{"abc"},
	}

	// This should NOT panic even though oid is < 12 chars
	summary := buildSummary(result)
	assert.Contains(t, summary, "abc")
	assert.NotContains(t, summary, "...")
}

func TestBuildSummary_EmptyGitOID_NoPanic(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs: []string{""},
	}

	// Empty string should not panic
	summary := buildSummary(result)
	assert.Contains(t, summary, "GitOID")
}

func TestBuildSummary_ExactlyTwelveChars(t *testing.T) {
	result := &cilockattest.Result{
		GitOIDs: []string{"123456789012"},
	}

	summary := buildSummary(result)
	// Exactly 12 chars — should NOT add "..." since there's nothing truncated
	assert.Contains(t, summary, "123456789012")
}

func TestBuildSummary_NoGitOIDs(t *testing.T) {
	result := &cilockattest.Result{
		AttestationFiles: []string{"/tmp/att.json"},
	}

	summary := buildSummary(result)
	assert.NotContains(t, summary, "GitOID")
	assert.Contains(t, summary, "att.json")
}

func TestBuildSummary_NoResults(t *testing.T) {
	result := &cilockattest.Result{}

	summary := buildSummary(result)
	assert.Contains(t, summary, "cilock-action Attestation")
}

func TestBuildSummary_MultipleFiles(t *testing.T) {
	result := &cilockattest.Result{
		AttestationFiles: []string{
			"/tmp/a.json",
			"/tmp/b-export.json",
		},
	}

	summary := buildSummary(result)
	assert.Contains(t, summary, "a.json")
	assert.Contains(t, summary, "b-export.json")
}

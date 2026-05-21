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
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/secretscan"
	"github.com/stretchr/testify/assert"
)

func TestParseCilockArgs_FailOnDetection(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantOpts int
	}{
		{name: "bare flag enables fail-on-detection", args: []string{"--attestor-secretscan-fail-on-detection"}, wantOpts: 1},
		{name: "inline true", args: []string{"--attestor-secretscan-fail-on-detection=true"}, wantOpts: 1},
		{name: "inline false still applies", args: []string{"--attestor-secretscan-fail-on-detection=false"}, wantOpts: 1},
		{name: "empty", args: nil, wantOpts: 0},
		{name: "unknown flag ignored", args: []string{"--unknown-flag", "--attestor-secretscan-fail-on-detection"}, wantOpts: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := parseCilockArgs(tc.args)
			assert.Len(t, opts, tc.wantOpts)
		})
	}
}

func TestParseCilockArgs_ValueFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantOpts int
	}{
		{name: "max-decode-layers inline", args: []string{"--attestor-secretscan-max-decode-layers=5"}, wantOpts: 1},
		{name: "max-decode-layers space-separated", args: []string{"--attestor-secretscan-max-decode-layers", "7"}, wantOpts: 1},
		{name: "max-decode-layers missing value is dropped", args: []string{"--attestor-secretscan-max-decode-layers"}, wantOpts: 0},
		{name: "max-decode-layers non-int dropped", args: []string{"--attestor-secretscan-max-decode-layers", "abc"}, wantOpts: 0},
		{name: "max-file-size", args: []string{"--attestor-secretscan-max-file-size", "100"}, wantOpts: 1},
		{name: "config-path", args: []string{"--attestor-secretscan-config-path", "/etc/gitleaks.toml"}, wantOpts: 1},
		{
			name:     "two flags compose",
			args:     []string{"--attestor-secretscan-fail-on-detection", "--attestor-secretscan-max-decode-layers=3"},
			wantOpts: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := parseCilockArgs(tc.args)
			assert.Len(t, opts, tc.wantOpts)
		})
	}
}

func TestBuildNamedAttestor_SecretscanAppliesOptions(t *testing.T) {
	opts := parseCilockArgs([]string{"--attestor-secretscan-fail-on-detection"})
	a, err := buildNamedAttestor("secretscan", opts)
	assert.NoError(t, err)
	assert.NotNil(t, a)
	_, ok := a.(*secretscan.Attestor)
	assert.True(t, ok, "expected *secretscan.Attestor")
}

func TestBuildNamedAttestor_UnknownAttestor(t *testing.T) {
	_, err := buildNamedAttestor("nope-not-a-real-attestor", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nope-not-a-real-attestor")
}

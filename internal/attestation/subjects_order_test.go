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

// jade:ring local

package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/cilock-action/internal/config"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/stretchr/testify/require"
)

// The action's subjects input leads the collection statement in the order
// given, the same as `cilock run --subjects`: JFrog Evidence binds evidence to
// the first subject.
func TestApplySubjectsOpt_SubjectsLeadInInputOrder(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)

	cfg := &config.Config{Subjects: []string{
		"zz-image=sha256:" + strings.Repeat("bb", 32),
		"app.tar=sha256:" + strings.Repeat("aa", 32),
	}}
	opts, err := applySubjectsOpt(cfg, []workflow.RunOption{workflow.RunWithSigners(signer)})
	require.NoError(t, err)

	results, err := workflow.RunWithExports("action-order", opts...)
	require.NoError(t, err)
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(results[len(results)-1].SignedEnvelope.Payload, &stmt))
	names := make([]string, 0, len(stmt.Subject))
	for _, s := range stmt.Subject {
		names = append(names, s.Name)
	}
	require.Equal(t, []string{"zz-image", "app.tar"}, names)
}

// Copyright 2026 TestifySec, Inc.
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

package platform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The CI OIDC opt-out is off unless the workflow sets it, on both platforms.
func TestInheritCIOIDCCredentialsInput(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		parse     func() (bool, error)
	}{
		{"github", "INPUT_INHERIT_CI_OIDC_CREDENTIALS", func() (bool, error) {
			c, err := ParseGitHub()
			if err != nil {
				return false, err
			}
			return c.InheritCIOIDCCredentials, nil
		}},
		{"gitlab", "CILOCK_INHERIT_CI_OIDC_CREDENTIALS", func() (bool, error) {
			c, err := ParseGitLab()
			if err != nil {
				return false, err
			}
			return c.InheritCIOIDCCredentials, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, "")
			got, err := tc.parse()
			require.NoError(t, err)
			require.False(t, got, "unset must mean scrub")

			t.Setenv(tc.key, "true")
			got, err = tc.parse()
			require.NoError(t, err)
			require.True(t, got)
		})
	}
}

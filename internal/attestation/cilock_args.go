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
	"strconv"
	"strings"

	"github.com/aflock-ai/rookery/plugins/attestors/secretscan"
)

// parseCilockArgs walks `cilock-args` for known attestor-config flags and
// translates them into typed option builders that buildAttestors() can
// apply when constructing the corresponding attestor.
//
// Background: cilock-action does NOT shell out to the cilock binary; it
// runs the rookery library in-process. So `--attestor-*` flags passed via
// the `cilock-args` input are otherwise inert — there's no cilock process
// to receive them. This helper closes that gap for the attestors users
// most often want to configure via cilock-args.
//
// Supported flags:
//   - --attestor-secretscan-fail-on-detection [bool]
//   - --attestor-secretscan-max-decode-layers <int>
//   - --attestor-secretscan-max-file-size <int-mb>
//   - --attestor-secretscan-config-path <path>
func parseCilockArgs(cilockArgs []string) (secretscanOpts []secretscan.Option) {
	for i := 0; i < len(cilockArgs); i++ {
		raw := cilockArgs[i]
		key, val, hasInlineVal := splitFlag(raw)

		nextValue := func() (string, bool) {
			if hasInlineVal {
				return val, true
			}
			if i+1 < len(cilockArgs) && !strings.HasPrefix(cilockArgs[i+1], "-") {
				i++
				return cilockArgs[i], true
			}
			return "", false
		}

		switch key {
		case "--attestor-secretscan-fail-on-detection":
			b := true
			if hasInlineVal {
				if parsed, err := strconv.ParseBool(val); err == nil {
					b = parsed
				}
			}
			secretscanOpts = append(secretscanOpts, secretscan.WithFailOnDetection(b))
		case "--attestor-secretscan-max-decode-layers":
			if v, ok := nextValue(); ok {
				if n, err := strconv.Atoi(v); err == nil {
					secretscanOpts = append(secretscanOpts, secretscan.WithMaxDecodeLayers(n))
				}
			}
		case "--attestor-secretscan-max-file-size":
			if v, ok := nextValue(); ok {
				if n, err := strconv.Atoi(v); err == nil {
					secretscanOpts = append(secretscanOpts, secretscan.WithMaxFileSize(n))
				}
			}
		case "--attestor-secretscan-config-path":
			if v, ok := nextValue(); ok {
				secretscanOpts = append(secretscanOpts, secretscan.WithConfigPath(v))
			}
		}
	}
	return secretscanOpts
}

// splitFlag splits "--key=value" into ("--key", "value", true). For bare
// "--key" it returns ("--key", "", false).
func splitFlag(raw string) (key, val string, hasInlineVal bool) {
	if idx := strings.Index(raw, "="); idx >= 0 {
		return raw[:idx], raw[idx+1:], true
	}
	return raw, "", false
}

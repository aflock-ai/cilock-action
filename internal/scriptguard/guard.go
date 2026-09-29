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

// Package scriptguard refuses to embed a script body that holds a credential.
//
// Under `script-capture: content` a script's body is signed into the
// attestation and stored permanently, so a credential in it cannot be
// withdrawn. Check runs before anything executes. It is a tripwire, not a
// proof: GitHub substitutes `${{ secrets.X }}` into the text before the action
// sees it, and the action cannot read repository secrets, so an opaque secret
// inlined that way is caught only when it has a known credential shape.
package scriptguard

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
)

// minSensitiveValueLen is the shortest environment value matched. Shorter
// values ("true", "1", "main") would match ordinary words in any script.
const minSensitiveValueLen = 8

type shape struct {
	rule string
	re   *regexp.Regexp
}

// credentialShapes are the credential formats recognised by their text alone.
// A minimum tail length keeps a bare prefix in prose ("tokens start with
// ghp_") from tripping the guard; real tokens are far longer.
//
// Each rule covers its whole family, not the common members: GitHub's
// ghp/gho/ghs/ghu/ghr (ghr is the refresh token), AWS long-term AKIA and
// temporary ASIA keys, and Slack's xoxa/b/c/d/e/p/r/s plus xapp app tokens
// (xoxc and xoxd are browser session credentials, xoxs legacy workspace
// tokens, xoxe rotating refresh tokens). Letters outside the family stay out,
// so prose such as "xoxo-" does not refuse a step.
var credentialShapes = []shape{
	{"github-token", regexp.MustCompile(`gh[porsu]_[A-Za-z0-9]{16,}`)},
	{"github-pat", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{16,}`)},
	{"aws-access-key-id", regexp.MustCompile(`A(KI|SI)A[0-9A-Z]{16}`)},
	{"slack-token", regexp.MustCompile(`xox[abcdeprs]-[A-Za-z0-9-]+|xapp-[0-9]+-[A-Za-z0-9-]+`)},
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
}

// Check returns an error when body contains a known credential shape, or the
// value of an environment variable (from env, "NAME=value" entries) whose name
// rookery's DefaultSensitiveEnvList names or globs. The error names the rule
// and the step and never contains the matched text.
func Check(step, body string, env []string) error {
	for _, s := range credentialShapes {
		if s.re.MatchString(body) {
			return refusal(step, s.rule)
		}
	}
	sensitive := attestation.DefaultSensitiveEnvList()
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || len(value) < minSensitiveValueLen || !isSensitiveName(name, sensitive) {
			continue
		}
		if strings.Contains(body, value) {
			return refusal(step, "sensitive-env:"+name)
		}
	}
	return nil
}

// isSensitiveName matches name against the list's exact entries and its `*`
// globs, case-insensitively, as the environment attestor does, with one
// narrowing.
//
// The list is tuned for the environment attestor, which OBFUSCATES a match, so
// over-matching costs nothing there. Here a match refuses the step, and two of
// its globs reach the filesystem locations every runner sets: `*PAT*` matches
// PATH, GITHUB_PATH and GITHUB_ACTION_PATH, and `*PWD*` matches PWD and OLDPWD.
// Their values are directories, which scripts spell out routinely. So PWD and
// OLDPWD are not sensitive, and "PATH" is removed from a name before the globs
// are tried: GITHUB_PAT and DEPLOY_PAT still match `*PAT*`, and SECRET_PATH
// still matches `*SECRET*`.
func isSensitiveName(name string, list map[string]struct{}) bool {
	upper := strings.ToUpper(name)
	if upper == "PWD" || upper == "OLDPWD" {
		return false
	}
	globbed := strings.ReplaceAll(upper, "PATH", "")
	for entry := range list {
		pattern := strings.ToUpper(entry)
		if !strings.Contains(pattern, "*") {
			if pattern == upper {
				return true
			}
			continue
		}
		// Environment names carry no '/', so path.Match's separator rule is
		// inert. A malformed pattern matches nothing.
		if ok, err := path.Match(pattern, globbed); err == nil && ok {
			return true
		}
	}
	return false
}

func refusal(step, rule string) error {
	return fmt.Errorf("script-capture guard refused step %q: its script matched rule %q, and under "+
		"script-capture: content the script is signed into the attestation and stored permanently "+
		"(the matched text is not shown). Pass the secret through env: and reference it as $NAME in "+
		"the script, or set script-capture: identity for this step to record only the script's digest. "+
		"A secret inlined with ${{ secrets.X }} is caught only when it has a known credential shape",
		step, rule)
}

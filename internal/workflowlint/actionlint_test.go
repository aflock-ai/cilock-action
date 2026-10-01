// jade:ring local

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

package workflowlint

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rhysd/actionlint"
)

// TestReusableWorkflowsPassActionlint runs actionlint over this repository's
// workflows. The monorepo's workflow-lint step lints only the root
// .github/workflows, so without this nothing lints a subtree's. shellcheck
// lints run: scripts when it is on PATH (CI's actionlint job installs it and
// fails closed without it; here its absence only drops that rule).
func TestReusableWorkflowsPassActionlint(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "provenance.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflow to lint: %v", err)
	}
	opts := &actionlint.LinterOptions{}
	if sc, err := exec.LookPath("shellcheck"); err == nil {
		opts.Shellcheck = sc
	} else {
		t.Log("shellcheck not on PATH: run: scripts are not shellchecked")
	}
	var out bytes.Buffer
	linter, err := actionlint.NewLinter(&out, opts)
	if err != nil {
		t.Fatal(err)
	}
	errs, err := linter.LintFiles(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) > 0 {
		t.Fatalf("actionlint found %d problem(s):\n%s", len(errs), out.String())
	}
}

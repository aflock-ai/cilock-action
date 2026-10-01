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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// provenance.yml is the isolated signer `cilock verify --slsa-level 3`
// trusts (attestation/slsa/l3 in rookery; Lean: SlsaL3Workflow.lean). The L3
// argument holds only while these properties do.

type workflow struct {
	On          map[string]yaml.Node `yaml:"on"`
	Permissions yaml.Node            `yaml:"permissions"`
	Jobs        map[string]job       `yaml:"jobs"`
}

type job struct {
	If          string            `yaml:"if"`
	RunsOn      yaml.Node         `yaml:"runs-on"`
	Permissions yaml.Node         `yaml:"permissions"`
	Uses        string            `yaml:"uses"`
	Env         map[string]string `yaml:"env"`
	Steps       []step            `yaml:"steps"`
}

type step struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]string `yaml:"with"`
}

func loadProvenance(t *testing.T) (workflow, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "provenance.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w, string(raw)
}

// permissionsOf decodes a permissions node: "{}" or a mapping.
func permissionsOf(t *testing.T, n yaml.Node) map[string]string {
	t.Helper()
	if n.Kind == 0 {
		t.Fatal("permissions is not set; an unset block inherits the caller's")
	}
	out := map[string]string{}
	if err := n.Decode(&out); err != nil {
		t.Fatalf("permissions must be a mapping: %v", err)
	}
	return out
}

func TestProvenanceWorkflowIsOnlyAReusableWorkflow(t *testing.T) {
	w, _ := loadProvenance(t)
	if len(w.On) != 1 {
		t.Fatalf("triggers %v; want workflow_call only", w.On)
	}
	if _, ok := w.On["workflow_call"]; !ok {
		t.Fatal("not a reusable workflow")
	}
	if p := permissionsOf(t, w.Permissions); len(p) != 0 {
		t.Fatalf("workflow-level permissions %v; want {} so only the provenance job holds a token", p)
	}
}

// A hosted runner, spelled literally: a runs-on expression or input would let
// the caller choose a self-hosted runner, which reads the job's token (Lean
// self_hosted_runner_accepted).
func TestProvenanceWorkflowRunsOnAHardCodedHostedRunner(t *testing.T) {
	w, _ := loadProvenance(t)
	hosted := regexp.MustCompile(`^ubuntu-\d+\.\d+$`)
	for name, j := range w.Jobs {
		if j.RunsOn.Kind != yaml.ScalarNode || !hosted.MatchString(j.RunsOn.Value) {
			t.Errorf("job %s runs-on %q; want a literal GitHub-hosted ubuntu-NN.NN label", name, j.RunsOn.Value)
		}
	}
}

// Requirement 5: the signing job runs only for push, release and
// workflow_dispatch, and every other event fails loudly.
func TestProvenanceWorkflowRefusesOutsiderTriggers(t *testing.T) {
	w, _ := loadProvenance(t)
	prov, ok := w.Jobs["provenance"]
	if !ok {
		t.Fatal("no provenance job")
	}
	want := "github.event_name == 'push' || github.event_name == 'release' || github.event_name == 'workflow_dispatch'"
	if strings.TrimSpace(prov.If) != want {
		t.Fatalf("provenance job if: %q\nwant: %q", prov.If, want)
	}
	refuse, ok := w.Jobs["refuse-trigger"]
	if !ok {
		t.Fatal("no refuse-trigger job: an outsider-triggered run would skip silently instead of failing")
	}
	if strings.TrimSpace(refuse.If) != "!("+want+")" {
		t.Fatalf("refuse-trigger if: %q; want the exact negation", refuse.If)
	}
	failed := false
	for _, s := range refuse.Steps {
		failed = failed || strings.Contains(s.Run, "exit 1")
	}
	if !failed {
		t.Fatal("refuse-trigger never fails")
	}
}

// Only the provenance job may mint an OIDC token.
func TestProvenanceWorkflowIDTokenInTheSigningJobOnly(t *testing.T) {
	w, _ := loadProvenance(t)
	for name, j := range w.Jobs {
		p := permissionsOf(t, j.Permissions)
		if name == "provenance" {
			if len(p) != 1 || p["id-token"] != "write" {
				t.Errorf("provenance job permissions %v; want exactly id-token: write", p)
			}
			continue
		}
		if len(p) != 0 {
			t.Errorf("job %s permissions %v; want {}", name, p)
		}
	}
}

// No caller code: no checkout, no local action (./ resolves to the caller's
// workspace), no reusable-workflow call-out, and every external action pinned
// by commit.
func TestProvenanceWorkflowRunsNoCallerCode(t *testing.T) {
	w, _ := loadProvenance(t)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	for name, j := range w.Jobs {
		if j.Uses != "" {
			t.Errorf("job %s calls another workflow %q", name, j.Uses)
		}
		for _, s := range j.Steps {
			switch {
			case s.Uses == "":
			case strings.HasPrefix(s.Uses, "actions/checkout"):
				t.Errorf("job %s step %q checks out code", name, s.Name)
			case strings.HasPrefix(s.Uses, "./") || strings.HasPrefix(s.Uses, "docker://"):
				t.Errorf("job %s step %q runs %q", name, s.Name, s.Uses)
			case !pinned.MatchString(s.Uses):
				t.Errorf("job %s step %q uses %q, not pinned by a 40-hex commit", name, s.Name, s.Uses)
			}
		}
	}
}

// The pwn-request pattern: an expression expanded into a run: script is
// shell code the caller wrote. Every value reaches scripts through env.
func TestProvenanceWorkflowInterpolatesNothingIntoRun(t *testing.T) {
	w, raw := loadProvenance(t)
	for name, j := range w.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, "${{") {
				t.Errorf("job %s step %q expands an expression inside run:", name, s.Name)
			}
		}
	}
	// inputs.* appears only as a whole env value.
	envOnly := regexp.MustCompile(`^\s+[A-Z_]+: \$\{\{ inputs\.[a-z-]+ \}\}\s*$`)
	for i, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "inputs.") && strings.Contains(line, "${{") && !envOnly.MatchString(line) {
			t.Errorf("line %d reads an input outside an env value: %q", i+1, strings.TrimSpace(line))
		}
	}
	subjectsViaEnv := false
	for _, s := range w.Jobs["provenance"].Steps {
		subjectsViaEnv = subjectsViaEnv || s.Env["SUBJECTS"] == "${{ inputs.subjects }}"
	}
	if !subjectsViaEnv {
		t.Fatal("subjects do not reach the statement step through env SUBJECTS")
	}
}

// Platform Fulcio is the default signer; public Sigstore is an opt-in
// boolean, and cilock's version is pinned in the workflow (with the
// installer's digest), never an input.
func TestProvenanceWorkflowSignerInputs(t *testing.T) {
	w, raw := loadProvenance(t)
	var call struct {
		Inputs map[string]struct {
			Type     string `yaml:"type"`
			Required bool   `yaml:"required"`
			Default  any    `yaml:"default"`
		} `yaml:"inputs"`
	}
	node := w.On["workflow_call"]
	if err := node.Decode(&call); err != nil {
		t.Fatal(err)
	}
	if in, ok := call.Inputs["public-sigstore"]; !ok || in.Type != "boolean" || in.Default != false {
		t.Errorf("public-sigstore input %+v; want boolean defaulting to false", in)
	}
	if in, ok := call.Inputs["subjects"]; !ok || !in.Required || in.Type != "string" {
		t.Errorf("subjects input %+v; want a required string", in)
	}
	for name := range call.Inputs {
		if strings.Contains(name, "version") || strings.Contains(name, "url") && name != "platform-url" || strings.Contains(name, "runner") {
			t.Errorf("input %q lets the caller choose what runs or where", name)
		}
	}
	if !regexp.MustCompile(`CILOCK_INSTALLER_SHA256: [0-9a-f]{64}`).MatchString(raw) {
		t.Error("the cilock installer is not pinned by SHA-256")
	}
}

// jade:ring local

// Package gitlab_test holds the GitLab CI include templates to what cilock and
// the platform accept. The templates are YAML a GitLab runner interprets, so
// these tests read them the way GitLab does (spec header, then the job
// document) and run the shell they carry.
package gitlab_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const platformTemplate = "cilock-platform.gitlab-ci.yml"

// docs returns the template's YAML documents: GitLab's `spec:` header, then
// the job definitions.
func docs(t *testing.T, name string) (spec, body map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var out []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, d)
	}
	if len(out) != 2 {
		t.Fatalf("%s: want a spec header and one job document, got %d documents", name, len(out))
	}
	return out[0], out[1]
}

// TestPlatformTemplateDeclaresOneTokenPerDoor: the include declares exactly
// the three ID tokens cilock selects, each for exactly one audience. A token
// for several audiences is refused by cilock (cijobtoken), and a sigstore
// token must never double as an upload credential.
func TestPlatformTemplateDeclaresOneTokenPerDoor(t *testing.T) {
	_, body := docs(t, platformTemplate)
	job, ok := body[".cilock"].(map[string]any)
	if !ok {
		t.Fatal("no .cilock job to extend")
	}
	tokens, ok := job["id_tokens"].(map[string]any)
	if !ok {
		t.Fatal(".cilock declares no id_tokens")
	}
	want := map[string]string{
		"SIGSTORE_ID_TOKEN":          "sigstore",
		"CILOCK_ARCHIVISTA_ID_TOKEN": "$[[ inputs.platform_url ]]/archivista",
		"CILOCK_LOGIN_ID_TOKEN":      "$[[ inputs.platform_url ]]/login",
	}
	if len(tokens) != len(want) {
		t.Errorf("id_tokens has %d entries, want exactly %d: %v", len(tokens), len(want), tokens)
	}
	for name, aud := range want {
		tok, ok := tokens[name].(map[string]any)
		if !ok {
			t.Errorf("id_tokens.%s missing", name)
			continue
		}
		got, isString := tok["aud"].(string)
		if !isString {
			t.Errorf("id_tokens.%s.aud is %T; it must be one audience string, never a list", name, tok["aud"])
			continue
		}
		if got != aud {
			t.Errorf("id_tokens.%s.aud = %q, want %q", name, got, aud)
		}
	}
}

// TestPlatformTemplateInputs: platform_url is required (no default, so an
// include without it fails at GitLab's lint rather than signing against
// nothing), and cilock_sha256 defaults to empty (take the hash the platform
// lists).
func TestPlatformTemplateInputs(t *testing.T) {
	spec, _ := docs(t, platformTemplate)
	inputs := spec["spec"].(map[string]any)["inputs"].(map[string]any)
	pu, ok := inputs["platform_url"].(map[string]any)
	if !ok {
		t.Fatal("spec.inputs.platform_url missing")
	}
	if _, has := pu["default"]; has {
		t.Error("platform_url has a default; it must be required")
	}
	sha, ok := inputs["cilock_sha256"].(map[string]any)
	if !ok || sha["default"] != "" {
		t.Errorf("cilock_sha256 must default to empty, got %v", inputs["cilock_sha256"])
	}
}

// setupScript is the .cilock before_script.
func setupScript(t *testing.T) string {
	t.Helper()
	_, body := docs(t, platformTemplate)
	bs := body[".cilock"].(map[string]any)["before_script"].([]any)
	if len(bs) != 1 {
		t.Fatalf("before_script has %d entries, want 1", len(bs))
	}
	return bs[0].(string)
}

// cilockFunc is the shell wrapper the setup defines.
func cilockFunc(t *testing.T) string {
	t.Helper()
	s := setupScript(t)
	start := strings.Index(s, "cilock() {")
	if start < 0 {
		t.Fatal("setup defines no cilock() wrapper")
	}
	end := strings.Index(s[start:], "\n}\n")
	if end < 0 {
		t.Fatal("cilock() wrapper is not closed")
	}
	return s[start : start+end+3]
}

// TestPlatformTemplateWrapperAddsThePlatformOnce runs the wrapper against a
// stub cilock: the platform subcommands get --platform-url once, a run that
// already names a platform or --offline is passed through untouched, the
// wrapped command's own arguments are never read, and other subcommands are
// passed through.
func TestPlatformTemplateWrapperAddsThePlatformOnce(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "cilock")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho \"$*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fn := cilockFunc(t)
	for _, c := range []struct{ args, want string }{
		{"run --step build -- make", "run --platform-url https://p.example --step build -- make"},
		{"login --product x", "login --platform-url https://p.example --product x"},
		{"trust gitlab g/p", "trust --platform-url https://p.example gitlab g/p"},
		{"run --platform-url https://other -- make", "run --platform-url https://other -- make"},
		{"run --offline -- make", "run --offline -- make"},
		{"run -- tool --platform-url x", "run --platform-url https://p.example -- tool --platform-url x"},
		{"version", "version"},
	} {
		script := fn + "\ncilock " + c.args + "\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TESTIFYSEC_PLATFORM_URL=https://p.example")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cilock %s: %v\n%s", c.args, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("cilock %s\n got: %s\nwant: %s", c.args, got, c.want)
		}
	}
}

// TestPlatformTemplateVerifiesTheBinary: the setup checks cilock's sha256
// before running it and exits when it has no hash to check against, so a
// tampered or unlisted binary never runs.
func TestPlatformTemplateVerifiesTheBinary(t *testing.T) {
	s := setupScript(t)
	verify := strings.Index(s, "sha256sum -c")
	noHash := strings.Index(s, `if [ -z "$want" ]; then echo`)
	chmod := strings.Index(s, "chmod +x")
	first := strings.Index(s, "cilock version")
	if verify < 0 || noHash < 0 || chmod < 0 || first < 0 {
		t.Fatalf("setup lacks a step: verify=%d no-hash exit=%d chmod=%d first run=%d", verify, noHash, chmod, first)
	}
	if noHash >= verify || verify >= chmod || chmod >= first {
		t.Errorf("the binary must be refused without a hash, verified, then made executable, then run; got offsets %d, %d, %d, %d",
			noHash, verify, chmod, first)
	}
}

// TestPlatformTemplateInstallsIntoAPrivateDirectory: on a shared runner
// another user can pre-create a predictable /tmp/cilock-<job id>, or plant a
// symlink there, and swap the binary between download and run. The setup must
// install into a fresh, owner-only directory with an unpredictable name, and
// must never write through what sits at the old predictable path.
func TestPlatformTemplateInstallsIntoAPrivateDirectory(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	for _, plant := range []string{"directory", "symlink"} {
		t.Run(plant, func(t *testing.T) {
			bin := t.TempDir()
			for name, body := range map[string]string{
				// curl writes the "download" to the -o path; sha256sum accepts it.
				"curl":      "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\nprintf '#!/bin/sh\\necho ok\\n' > \"$out\"\n",
				"sha256sum": "#!/bin/sh\nexit 0\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			tmp, victim := t.TempDir(), t.TempDir()
			predictable := filepath.Join(tmp, "cilock-4242")
			if plant == "directory" {
				if err := os.Mkdir(predictable, 0o777); err != nil {
					t.Fatal(err)
				}
				victim = predictable
			} else if err := os.Symlink(victim, predictable); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", setupScript(t)+"\nprintf 'DIR=%s\\n' \"$cilock_dir\"\n")
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp, "CI_JOB_ID=4242",
				"TESTIFYSEC_PLATFORM_URL=https://p.example", "TESTIFYSEC_CILOCK_SHA256="+strings.Repeat("a", 64))
			cmd.Env = append(cmd.Env, "CI_BUILDS_DIR=")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("setup: %v\n%s", err, out)
			}
			var dir string
			for _, l := range strings.Split(string(out), "\n") {
				if v, ok := strings.CutPrefix(l, "DIR="); ok {
					dir = v
				}
			}
			if dir == "" || dir == predictable {
				t.Fatalf("installed into %q; want an unpredictable directory, not %s", dir, predictable)
			}
			fi, err := os.Lstat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o700 {
				t.Errorf("%s is %v; want a real 0700 directory", dir, fi.Mode())
			}
			if _, err := os.Stat(filepath.Join(victim, "cilock")); err == nil {
				t.Errorf("a cilock binary was written into %s, which another user controls", victim)
			}
		})
	}
}

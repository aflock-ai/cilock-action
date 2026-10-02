// jade:ring local

package gitlab_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const legacyTemplate = "cilock.gitlab-ci.yml"

// bannedInAirGap are the hosts and images a template must never name: an
// air-gapped appliance reaches the platform and the operator's registry only.
// The scan reads comments and examples too, so a copy-pasted include cannot
// bring them back.
var bannedInAirGap = regexp.MustCompile(`(?i)github\.com|githubusercontent|ghcr\.io|docker\.io|golang:`)

func TestTemplatesNameNoPublicHostOrImage(t *testing.T) {
	for _, name := range []string{platformTemplate, legacyTemplate} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if m := bannedInAirGap.FindString(line); m != "" {
				t.Errorf("%s:%d names %q, unreachable in an air gap: %s", name, i+1, m, strings.TrimSpace(line))
			}
		}
	}
}

// TestPlatformTemplateImageIsAnInput: the container image comes from an input
// with a default, and the job uses it, so a private registry mirror is one
// include line.
func TestPlatformTemplateImageIsAnInput(t *testing.T) {
	spec, body := docs(t, platformTemplate)
	in, ok := spec["spec"].(map[string]any)["inputs"].(map[string]any)["image"].(map[string]any)
	if !ok {
		t.Fatal("spec.inputs.image missing")
	}
	if def, _ := in["default"].(string); def == "" {
		t.Errorf("image needs a non-empty default (GitLab refuses an empty image); got %v", in["default"])
	}
	if got := body[".cilock"].(map[string]any)["image"]; got != "$[[ inputs.image ]]" {
		t.Errorf(".cilock.image = %v, want $[[ inputs.image ]]", got)
	}
}

func legacyJob(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(legacyTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	job, ok := doc[".cilock"].(map[string]any)
	if !ok {
		t.Fatal("no .cilock job")
	}
	return job
}

// TestLegacyTemplateSetsNoImage: the job's own image (or the runner default,
// which an air-gapped operator points at a private registry) is used.
func TestLegacyTemplateSetsNoImage(t *testing.T) {
	if img, has := legacyJob(t)["image"]; has {
		t.Errorf(".cilock sets image %v; it must leave the image to the job", img)
	}
}

func legacySetup(t *testing.T) string {
	t.Helper()
	bs, ok := legacyJob(t)["before_script"].([]any)
	if !ok || len(bs) != 1 {
		t.Fatalf("before_script: want one entry, got %v", legacyJob(t)["before_script"])
	}
	return bs[0].(string)
}

func runLegacySetup(t *testing.T, env ...string) (string, string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	bin, logDir := t.TempDir(), t.TempDir()
	log := filepath.Join(logDir, "curl.log")
	for name, body := range map[string]string{
		"curl":      "#!/bin/sh\necho \"$@\" >> " + log + "\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n: > \"$out\"\n",
		"sha256sum": "#!/bin/sh\nexit 0\n",
		"tar":       "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -C ] && d=$2; shift; done\nprintf '#!/bin/sh\\necho v\\n' > \"$d/cilock-action\"\n",
		"grep":      "#!/bin/sh\nexit 0\n",
		"uname":     "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Redirect the install dir and /tmp so nothing is installed for real.
	// The /tmp rewrite must run first: the temp dirs themselves may live under /tmp.
	script := strings.ReplaceAll(legacySetup(t), "/tmp", logDir)
	script = strings.ReplaceAll(script, "/usr/local/bin", bin)
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "CILOCK_VERSION=v1.2.3"}, env...)
	out, err := cmd.CombinedOutput()
	logged, _ := os.ReadFile(log)
	return string(out), string(logged), err
}

// TestLegacyTemplateRefusesWithoutADownloadBase: with no mirror named the setup
// stops and names the variable; it must not fall back to a public host.
func TestLegacyTemplateRefusesWithoutADownloadBase(t *testing.T) {
	out, logged, err := runLegacySetup(t)
	if err == nil {
		t.Fatalf("setup succeeded with no CILOCK_ACTION_BASE_URL:\n%s", out)
	}
	if !strings.Contains(out, "CILOCK_ACTION_BASE_URL") {
		t.Errorf("error does not name the variable:\n%s", out)
	}
	if logged != "" {
		t.Errorf("curl ran before the check: %s", logged)
	}
}

// TestLegacyTemplateDownloadsOnlyFromTheConfiguredBase: every fetch goes to
// <base>/<version>/<asset>; a trailing slash on the base changes nothing, and a
// non-https base is refused.
func TestLegacyTemplateDownloadsOnlyFromTheConfiguredBase(t *testing.T) {
	for _, base := range []string{"https://mirror.corp.internal/cilock-action", "https://mirror.corp.internal/cilock-action/"} {
		out, logged, err := runLegacySetup(t, "CILOCK_ACTION_BASE_URL="+base)
		if err != nil {
			t.Fatalf("base %q: %v\n%s", base, err, out)
		}
		lines := strings.Split(strings.TrimSpace(logged), "\n")
		if len(lines) != 2 {
			t.Fatalf("want 2 fetches (asset, checksums), got %q", logged)
		}
		for _, l := range lines {
			if !strings.Contains(l, "https://mirror.corp.internal/cilock-action/v1.2.3/") {
				t.Errorf("fetch outside <base>/<version>/: %s", l)
			}
		}
	}
	for _, bad := range []string{"http://mirror.corp.internal/x", "ftp://x/y", "mirror.corp.internal/x", "file:///etc"} {
		if out, _, err := runLegacySetup(t, "CILOCK_ACTION_BASE_URL="+bad); err == nil {
			t.Errorf("base %q accepted:\n%s", bad, out)
		}
	}
}

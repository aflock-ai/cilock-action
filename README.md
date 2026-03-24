# cilock

Protecting against malicious GitHub Actions and compromised packages.

Somebody rewrote trivy-action. 75 of 76 version tags. Nobody noticed for hours. Five days later, `litellm==1.82.8` on PyPI shipped a `.pth` credential stealer that runs on every Python interpreter startup — no import needed. Same encryption scheme, same exfiltration pattern. This isn't two incidents. It's a playbook.

The industry response was "pin your SHAs." That's one lock on a building that needs three.

cilock provides those three locks: **prevention**, **content detection**, and **behavioral detection**. Every attestation is cryptographically signed and timestamped. Not logging — tamper-evident proof of what ran and whether it met policy.

Pinning is a lock. Attestation is a security camera, a receipt, and a notary.

## Three Layers That Kill These Attacks

### Layer 1: Prevention — Don't Run Untrusted Code

Restrict your actions to an approved catalog: internal forks, Chainguard Actions, or GitHub's official `actions/*` namespace. Then enforce it with policy:

```rego
package cilock.verify

import rego.v1

approved_sources := ["chainguard-dev/", "your-org/", "actions/"]

deny contains msg if {
    not source_approved(input.actionref)
    msg := sprintf("Action from untrusted source: %s", [input.actionref])
}

deny contains msg if {
    not input.refpinned
    msg := sprintf("Action not pinned to SHA: %s", [input.actionref])
}
```

Tag rewrite is irrelevant if you enforce source and SHA pinning. Proven in CI — this policy denied `actions/setup-node@v4` with "Action not pinned to SHA" through a full cilock verify pipeline with Fulcio OIDC signing and Sigstore TSA timestamps.

### Layer 2: Content Detection — Catch Credential Leakage

If prevention fails — a trusted source is compromised, a human overrides a check — cilock's secretscan attestor catches credential patterns in the command output. It runs Gitleaks pattern detection on stdout and recursively decodes base64, hex, and URL-encoded content through multiple layers.

The LiteLLM attacker used double base64 encoding. That's decoded at depth 1, revealing the inner base64. Decoded again at depth 2, the credential harvesting script is exposed. `--attestor-secretscan-fail-on-detection` blocks the build.

### Layer 3: Behavioral Detection — Catch What the Attacker Does, Not What They Print

The real TeamPCP stealer was designed for covert operation. Credentials went to files, not stdout. Content scanning alone would miss it. cilock's `--trace` flag uses Linux ptrace to intercept syscalls and record every file each process opens. An OPA policy then flags the filesystem access patterns that credential harvesting produces:

```rego
deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    startswith(file, "/tmp/runner_collected")
    msg := sprintf("Credential harvesting: %s (PID %d) opened %s",
        [proc.program, proc.processid, file])
}
```

No legitimate `pip install` or `pytest` process reads SSH keys, AWS credentials, and Kubernetes configs. A single process touching 3+ credential directories is a signal with essentially zero false positive rate in a CI/CD pipeline.

Content scanning catches what the attacker prints. Behavioral detection catches what the attacker does. Prevention stops the attacker from running at all.

## Cryptographic Verification — Not Just Logging

Every cilock attestation is signed with Fulcio OIDC (short-lived certificates tied to GitHub Actions identity), timestamped by Sigstore TSA (RFC 3161), and verified against a signed Rego policy. `cilock verify` validates the signature chain, checks the timestamp, and evaluates the policy. If anything fails, the release is blocked.

This is cryptographic proof of what ran, when it ran, what it produced, and whether it met policy — with a tamper-evident chain from the CI runner to the policy decision.

## Quick Start

### Wrap a shell command

```yaml
- uses: aflock-ai/cilock-action@v0.0.1
  with:
    step: build
    command: "npm run build"
```

### Wrap a GitHub Action

```yaml
- uses: aflock-ai/cilock-action@v0.0.1
  with:
    step: trivy-scan
    action-ref: "aquasecurity/trivy-action@7b7aa264d718dc28d43f6a611f86ab9880e3d87a"
    action-inputs: '{"image-ref": "myapp:latest", "format": "sarif"}'
```

### Enable secret scanning with build blocking

```yaml
- uses: aflock-ai/cilock-action@v0.0.1
  with:
    step: install-deps
    command: "pip install -r requirements.txt"
    attestations: "environment git github secretscan"
    cilock-args: "--attestor-secretscan-fail-on-detection"
```

### Enable behavioral tracing

```yaml
- uses: aflock-ai/cilock-action@v0.0.1
  with:
    step: install-deps
    command: "npm install"
    trace: "true"
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `step` | Step name for attestation (required) | — |
| `command` | Shell command to run | — |
| `action-ref` | GitHub Action to wrap (`owner/repo@ref`) | — |
| `action-inputs` | JSON map of inputs for wrapped action | — |
| `attestations` | Space-separated attestor list | `environment git github` |
| `trace` | Enable syscall tracing | `false` |
| `enable-sigstore` | Enable Fulcio OIDC signing | `true` |
| `enable-archivista` | Store attestations in Archivista | `true` |
| `outfile` | Output file for signed envelope | — |
| `key` | Path to file-based signing key | — |
| `timestamp-servers` | Space-separated TSA URLs | TestifySec TSA |

See [`action.yml`](action.yml) for the full list.

## Outputs

| Output | Description |
|--------|-------------|
| `git_oid` | GitOID of stored attestation |
| `attestation_file` | Path to attestation output file |

## Signing Options

| Method | Inputs |
|--------|--------|
| **Sigstore/Fulcio** (default) | `enable-sigstore`, `fulcio-url`, `fulcio-oidc-client-id`, `fulcio-oidc-issuer` |
| **File-based** | `key`, `certificate`, `intermediates` |
| **KMS** | `kms-ref`, `kms-aws-profile`, `kms-gcp-credentials-file` |
| **Vault** | `vault-url`, `vault-token` |

## Proven Against Real Attacks

Everything was tested in a [public test repository](https://github.com/aflock-ai/cilock-trivy-detection-test) with live GitHub Actions workflow runs:

| Test | What It Proves |
|------|---------------|
| **Attack reproduction** | Reproduces the TeamPCP credential harvesting technique. Secretscan catches it — 4 findings at two encoding depths |
| **Covert variant** | Reproduces the file-based exfiltration pattern (nothing to stdout). Trace + OPA catches it |
| **Real Trivy scan** | Wraps actual `trivy image` against a Docker image. cilock works on production workloads |
| **Source policy** | OPA denies unpinned `actions/setup-node@v4` |
| **Clean baseline** | Zero false positives on clean builds |
| **Performance** | ~36% trace overhead on npm install (5.1s to 6.9s) |

All verified end-to-end with Fulcio OIDC + Sigstore TSA.

## What cilock Does Not Do

We'd rather you know upfront than discover in production.

- **Detection is post-execution.** cilock wraps the action and scans its output after it runs. If secrets are exfiltrated during execution, the exfiltration has already happened. cilock blocks the release and provides forensic evidence, but cannot prevent the initial exfiltration. Prevention layers are the first line of defense.
- **No network egress monitoring.** The HTTPS POST to the attacker's C2 domain would not be detected. [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) covers this gap.
- **Trace requires opt-in.** Behavioral detection needs `--trace` enabled and OPA rules defined. Without it, covert file-based attacks evade content scanning.
- **Novel exfiltration techniques can evade pattern matching.** Secretscan uses Gitleaks rules. Behavioral detection (trace + OPA) covers many of these cases by catching the filesystem access patterns rather than the content.

## Full Technical Breakdown

- [75 Poisoned Tags and Nobody Noticed](https://testifysec.com/blog/cilock-action-supply-chain-attacks) — Trivy attack analysis
- [A .pth File, 34KB of Base64, and Every Secret You Have](https://testifysec.com/blog/cilock-litellm-supply-chain-attack) — LiteLLM attack analysis

## Related

- [Rookery](https://github.com/aflock-ai/rookery) — the attestation framework cilock is built on
- [aflock](https://github.com/aflock-ai/aflock) — AI agent policy enforcement
- [TestifySec](https://testifysec.com) — the company behind these projects

## License

Apache License 2.0 — see [LICENSE](LICENSE).

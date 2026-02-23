# cilock GitLab CI Template

Reusable GitLab CI template for wrapping commands with rookery attestation.

## Quick Start

Include the template and extend `.cilock`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/aflock-ai/cilock-action/v1/gitlab/cilock.gitlab-ci.yml'

build:
  extends: .cilock
  variables:
    CILOCK_STEP: build
    CILOCK_COMMAND: "go build -o myapp ./cmd/myapp"
```

## Configuration

All configuration uses `CILOCK_*` environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `CILOCK_STEP` | Step name (required) | |
| `CILOCK_COMMAND` | Shell command to run (required) | |
| `CILOCK_VERSION` | Release version to download | `v1` |
| `CILOCK_ATTESTATIONS` | Space-separated attestor list | `environment git gitlab` |
| `CILOCK_ENABLE_ARCHIVISTA` | Store attestations in Archivista | `true` |
| `CILOCK_ARCHIVISTA_SERVER` | Archivista server URL | `https://web.platform.testifysec.com` |
| `CILOCK_ENABLE_SIGSTORE` | Enable Sigstore/Fulcio signing | `false` |
| `CILOCK_KEY` | Path to signing key (file signer) | |
| `CILOCK_OUTFILE` | Output file for signed envelope | |
| `CILOCK_TRACE` | Enable command tracing | `false` |
| `CILOCK_HASHES` | Hash algorithms | `sha256` |

## Outputs

The template produces a `cilock.env` dotenv artifact with:

- `git_oid` -- GitOID of the stored attestation
- `attestation_file` -- Path to the attestation output file

Reference outputs in downstream jobs:

```yaml
deploy:
  needs: [build]
  script:
    - echo "Attestation GitOID: ${git_oid}"
```

## Signing

Sigstore is disabled by default on GitLab (no native OIDC token).
Use a file-based signer or configure Fulcio with a custom OIDC issuer:

```yaml
build:
  extends: .cilock
  variables:
    CILOCK_STEP: build
    CILOCK_COMMAND: "make build"
    CILOCK_KEY: "${CI_PROJECT_DIR}/signing-key.pem"
```

## Examples

See [`examples/gitlab/`](../examples/gitlab/) for complete pipeline configurations.

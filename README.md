# cilock-action

GitHub Action that wraps a command (or another action) with [cilock](https://github.com/aflock-ai/rookery) attestation. Records what ran, what files it touched, what containers it pulled, and what credentials it leaked — all into a signed [in-toto](https://in-toto.io/) statement.

```yaml
- uses: aflock-ai/cilock-action@v1
  with:
    step: build
    attestations: "environment git github sbom secretscan"
    outfile: ${{ github.workspace }}/attestation.json
    command: make build
```

See [`action.yml`](action.yml) for every input.

## The `outfile` is a DSSE envelope, not a raw attestation

This trips up everyone the first time, including the people writing this README. The file at `outfile:` is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64-encoded in-toto Statement>",
  "signatures": [{ "keyid": "…", "sig": "…", "cert": "…" }]
}
```

The actual attestation content — `predicateType`, `subject`, `predicate.attestations[]` — lives **inside `.payload`, base64-encoded**. Treating the envelope as the statement leads to OPA policies that silently match nothing because `input.predicate` doesn't exist at the envelope level.

### Decode it before consuming

```bash
# Inspect the inner Statement
jq -r '.payload' attestation.json | base64 -d | jq .

# Predicate type
jq -r '.payload' attestation.json | base64 -d | jq -r '.predicateType'
# → https://aflock.ai/attestation-collection/v0.1

# Per-attestor entries (this is where secretscan findings, trace data, etc. live)
jq -r '.payload' attestation.json | base64 -d \
  | jq '.predicate.attestations[] | {type, attestation_keys: (.attestation | keys)}'
```

### Feed it to OPA

OPA Rego policies that match on `input.predicate.attestations[]` need the **decoded** statement, not the envelope. The right shape:

```bash
jq -r '.payload' attestation.json | base64 -d > /tmp/statement.json

opa eval -d policy.rego -i /tmp/statement.json 'data.cilock.verify.deny' -f json
```

If your policy expects a specific attestor's data at the top level (e.g. trace data from `command-run`), drill in one more layer:

```bash
jq '.predicate.attestations[] | .attestation | select(has("processes"))' /tmp/statement.json \
  > /tmp/trace-input.json

opa eval -d policy-trace.rego -i /tmp/trace-input.json 'data.cilock.verify.deny' -f json
```

### Why DSSE?

DSSE is what makes the signature meaningful — it covers the exact bytes of the payload (including `payloadType`), so downstream verifiers can prove what was signed without re-canonicalizing JSON. The base64 wrapping prevents whitespace and key-ordering changes from invalidating signatures.

The downside is the extra unwrap step. If you build CI checks against cilock attestations, write a small helper:

```bash
# decode_attestation.sh
jq -r '.payload' "$1" | base64 -d
```

…and use it everywhere.

## Inputs

See [`action.yml`](action.yml). The most-used ones:

| Input | Purpose |
|---|---|
| `step` | Step name embedded in the attestation (required) |
| `command` / `action-ref` | What to wrap (exactly one required) |
| `attestations` | Space-separated attestor list |
| `outfile` | Path for the DSSE envelope. **Format above.** |
| `trace` | Enable command tracing (`ptrace` on Linux) |
| `enable-sigstore` | Sign with Fulcio (default `true`) |
| `enable-archivista` | Upload to Archivista (default `true`) |
| `cilock-args` | Pass-through args to attestors (see [supported flags](#cilock-args-passthrough)) |

### `cilock-args` passthrough

cilock-action runs the rookery library in-process — it does not shell out to the cilock binary — so only flags that the action explicitly translates take effect. Currently supported:

- `--attestor-secretscan-fail-on-detection [bool]` — exit non-zero when secretscan records findings
- `--attestor-secretscan-max-decode-layers <int>` — how many encoding layers to recursively decode (default 3)
- `--attestor-secretscan-max-file-size <int-mb>` — skip files larger than this
- `--attestor-secretscan-config-path <path>` — custom Gitleaks config

Unknown flags are silently ignored. File an issue or PR if you need another attestor option wired through.

## Examples

### Wrap a command and assert on secretscan findings

```yaml
- uses: aflock-ai/cilock-action@v1
  with:
    step: build
    attestations: "environment git github secretscan"
    outfile: ${{ github.workspace }}/attestation.json
    cilock-args: "--attestor-secretscan-fail-on-detection"
    command: make build
```

### Wrap an upstream action (e.g. supply-chain hygiene)

```yaml
- uses: aflock-ai/cilock-action@v1
  with:
    step: trivy-scan
    attestations: "environment git github sbom"
    outfile: ${{ github.workspace }}/scan.attestation.json
    action-ref: aquasecurity/trivy-action@76071ef0d7ec1c61c8c2dc1a37a91019797d3c1b
    action-inputs: |
      {"scan-type": "fs", "scan-ref": "."}
```

### Verify in CI with OPA

```yaml
- uses: aflock-ai/cilock-action@v1
  with:
    step: build
    outfile: ${{ github.workspace }}/attestation.json
    command: make build

- name: Decode and verify
  run: |
    jq -r '.payload' attestation.json | base64 -d > /tmp/statement.json
    opa eval -d policy.rego -i /tmp/statement.json \
      'data.cilock.verify.deny' -f json | tee /tmp/opa-result.json
    DENY=$(jq -r '.result[0].expressions[0].value | length // 0' /tmp/opa-result.json)
    if [ "$DENY" -gt 0 ]; then
      echo "::error::policy denied $DENY rules"
      exit 1
    fi
```

## Versioning

- `@v1` — major-version tag, auto-updated on each `v1.x.y` release
- `@v1.0.1` — exact-tag pin
- `@<40-hex-SHA>` — SHA pin against the published-tag commit (recommended for supply-chain hygiene; the shim resolves the SHA to its release tag)

## Related

- **cilock** (the wrapped library): [aflock-ai/rookery](https://github.com/aflock-ai/rookery)
- **Docs**: [cilock.aflock.ai](https://cilock.aflock.ai)
- **Supply-chain attack catalog with live detection demos**: [aflock-ai/supply-chain-attacks](https://github.com/aflock-ai/supply-chain-attacks)
- **Commercial / managed**: [TestifySec Platform](https://testifysec.com/product)

## License

Apache 2.0. Built and sponsored by [TestifySec](https://testifysec.com).

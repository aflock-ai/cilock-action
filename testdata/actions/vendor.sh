#!/usr/bin/env bash
# Vendor the top 20 most popular GitHub Actions for offline testing.
# Usage: ./vendor.sh
set -euo pipefail

ACTIONS_DIR="$(cd "$(dirname "$0")" && pwd)"

# Top 20 most popular GitHub Actions by usage
ACTIONS=(
  "actions/checkout@v4"
  "actions/setup-node@v4"
  "actions/setup-go@v5"
  "actions/setup-python@v5"
  "actions/setup-java@v4"
  "actions/cache@v4"
  "actions/upload-artifact@v4"
  "actions/download-artifact@v4"
  "actions/github-script@v7"
  "actions/labeler@v5"
  "docker/setup-buildx-action@v3"
  "docker/build-push-action@v6"
  "docker/login-action@v3"
  "softprops/action-gh-release@v2"
  "peter-evans/create-pull-request@v7"
  "goreleaser/goreleaser-action@v6"
  "golangci/golangci-lint-action@v6"
  "codecov/codecov-action@v5"
  "anchore/sbom-action@v0"
  "sigstore/cosign-installer@v3"
)

for action in "${ACTIONS[@]}"; do
  # Parse owner/repo@ref
  ref="${action##*@}"
  path="${action%%@*}"
  owner="${path%%/*}"
  repo="${path#*/}"

  target_dir="${ACTIONS_DIR}/${owner}/${repo}/${ref}"

  if [ -d "$target_dir" ]; then
    echo "SKIP: $action (already vendored)"
    continue
  fi

  echo "VENDOR: $action"
  mkdir -p "$target_dir"

  # Download tarball from GitHub API
  url="https://api.github.com/repos/${owner}/${repo}/tarball/${ref}"
  if curl -sL -H "Accept: application/vnd.github+json" "$url" | tar xz --strip-components=1 -C "$target_dir" 2>/dev/null; then
    echo "  OK: $(du -sh "$target_dir" | cut -f1)"
  else
    echo "  FAIL: $action — trying git clone"
    rm -rf "$target_dir"
    mkdir -p "$target_dir"
    if git clone --depth=1 --branch "$ref" "https://github.com/${owner}/${repo}.git" "$target_dir" 2>/dev/null; then
      rm -rf "$target_dir/.git"
      echo "  OK (git): $(du -sh "$target_dir" | cut -f1)"
    else
      echo "  FAIL: could not vendor $action"
      rm -rf "$target_dir"
    fi
  fi
done

echo ""
echo "=== Vendored actions ==="
find "$ACTIONS_DIR" -name "action.yml" -o -name "action.yaml" | while read f; do
  dir=$(dirname "$f")
  rel="${dir#$ACTIONS_DIR/}"
  echo "  $rel"
done

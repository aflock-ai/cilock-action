// Pure resolution logic for the cilock-action shim: maps the runner's
// platform/arch to a release asset and the version ref to a download base URL.
// No I/O here — everything is unit-testable with `node --test` (resolve.test.js).

"use strict";

const REPO = "aflock-ai/cilock-action";

// The complete set of goos/goarch targets that cilock releases ship
// (mirrors the cilock release build matrix). Windows is deliberately
// absent: the cilock attestor stack (e.g. omnitrail) is linux/darwin-only,
// so no Windows binaries are released.
const SUPPORTED_TARGETS = [
  "linux/amd64",
  "linux/arm64",
  "darwin/amd64",
  "darwin/arm64",
];

// Node's process.platform → goos. win32 is handled separately for a
// clearer error message.
const OS_MAP = { linux: "linux", darwin: "darwin" };

// Node's process.arch → goarch.
const ARCH_MAP = { x64: "amd64", arm64: "arm64" };

function supportedList() {
  return SUPPORTED_TARGETS.join(", ");
}

// resolveAsset maps Node's (process.platform, process.arch) to the exact
// release asset name. Throws a clear error naming the supported set for
// anything outside it — never lets an unsupported runner fall through to
// an opaque 404.
function resolveAsset(platform, arch) {
  if (platform === "win32") {
    throw new Error(
      `cilock-action does not support Windows runners — cilock binaries are linux/darwin only. ` +
        `Supported targets: ${supportedList()}. Use an ubuntu-* or macos-* runner.`,
    );
  }

  const goos = OS_MAP[platform];
  const goarch = ARCH_MAP[arch];
  if (!goos || !goarch || !SUPPORTED_TARGETS.includes(`${goos}/${goarch}`)) {
    throw new Error(
      `unsupported runner platform/arch: ${platform}/${arch}. ` +
        `Supported targets: ${supportedList()}.`,
    );
  }

  return { goos, goarch, assetName: `cilock-action_${goos}_${goarch}.tar.gz` };
}

// resolveBaseURL maps the version input / GITHUB_ACTION_REF to a GitHub
// release download base URL.
//
// Only full release tags (vX.Y.Z, including pre-releases like v1.0.5-rc14)
// have a GitHub Release of their own. Everything else — "latest", branch
// refs (main, dev), full commit-SHA pins, and the floating major/minor
// alias tags (v1, v2, v1.0) — has NO release attached, so a
// releases/download/<ref>/ URL would 404. All of those resolve to the
// latest release instead.
function resolveBaseURL(rawVersion) {
  const v = (rawVersion || "").trim();

  if (/^v?\d+\.\d+\.\d+/.test(v)) {
    const tag = `v${v.replace(/^v/, "")}`;
    return {
      tag,
      baseURL: `https://github.com/${REPO}/releases/download/${tag}`,
    };
  }

  return {
    tag: "latest",
    baseURL: `https://github.com/${REPO}/releases/latest/download`,
  };
}

// parseChecksums extracts the sha256 hex digest for assetName from a
// goreleaser checksums.txt body ("<hex>  <filename>" per line). Throws if
// the asset has no entry — a release missing its checksum is not trusted.
function parseChecksums(text, assetName) {
  for (const line of (text || "").split("\n")) {
    const m = line.trim().match(/^([0-9a-fA-F]{64})[ \t*]+(\S+)$/);
    if (m && m[2] === assetName) {
      return m[1].toLowerCase();
    }
  }
  throw new Error(`checksums.txt has no entry for ${assetName}`);
}

module.exports = {
  SUPPORTED_TARGETS,
  resolveAsset,
  resolveBaseURL,
  parseChecksums,
};

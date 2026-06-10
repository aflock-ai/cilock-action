"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  SUPPORTED_TARGETS,
  resolveAsset,
  resolveBaseURL,
  parseChecksums,
} = require("./resolve");

test("supported targets mirror the cilock release matrix exactly", () => {
  assert.deepEqual(SUPPORTED_TARGETS, [
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
  ]);
});

test("resolveAsset maps every supported (platform, arch) pair to the exact tarball", () => {
  // (process.platform, process.arch) → release asset, one row per GitHub
  // runner family: ubuntu-latest, ubuntu-24.04-arm, macos-13, macos-latest.
  const cases = [
    ["linux", "x64", "cilock-action_linux_amd64.tar.gz"],
    ["linux", "arm64", "cilock-action_linux_arm64.tar.gz"],
    ["darwin", "x64", "cilock-action_darwin_amd64.tar.gz"],
    ["darwin", "arm64", "cilock-action_darwin_arm64.tar.gz"],
  ];
  for (const [platform, arch, want] of cases) {
    const got = resolveAsset(platform, arch);
    assert.equal(got.assetName, want, `${platform}/${arch}`);
  }
});

test("resolveAsset maps x64 to amd64 and passes arm64 through", () => {
  assert.equal(resolveAsset("linux", "x64").goarch, "amd64");
  assert.equal(resolveAsset("linux", "arm64").goarch, "arm64");
  assert.equal(resolveAsset("darwin", "x64").goarch, "amd64");
  assert.equal(resolveAsset("darwin", "arm64").goarch, "arm64");
});

test("resolveAsset rejects windows runners with a clear unsupported error", () => {
  for (const arch of ["x64", "arm64", "ia32"]) {
    assert.throws(
      () => resolveAsset("win32", arch),
      /does not support Windows runners/,
      `win32/${arch} must name Windows explicitly`,
    );
    assert.throws(
      () => resolveAsset("win32", arch),
      /linux\/amd64, linux\/arm64, darwin\/amd64, darwin\/arm64/,
      `win32/${arch} must name the supported set`,
    );
  }
});

test("resolveAsset rejects unsupported platform/arch pairs naming the supported set", () => {
  const cases = [
    ["linux", "ppc64"],
    ["linux", "s390x"],
    ["linux", "riscv64"],
    ["linux", "ia32"],
    ["darwin", "ppc64"],
    ["freebsd", "x64"],
    ["aix", "ppc64"],
    ["sunos", "x64"],
  ];
  for (const [platform, arch] of cases) {
    assert.throws(
      () => resolveAsset(platform, arch),
      /unsupported runner platform\/arch/,
      `${platform}/${arch} must throw`,
    );
    assert.throws(
      () => resolveAsset(platform, arch),
      /linux\/amd64, linux\/arm64, darwin\/amd64, darwin\/arm64/,
      `${platform}/${arch} must name the supported set`,
    );
  }
});

test("resolveBaseURL pins full release tags (the only refs with a release)", () => {
  const cases = [
    ["v1.0.4", "v1.0.4"],
    ["1.0.4", "v1.0.4"],
    ["v1.0.5-rc14", "v1.0.5-rc14"],
    ["v2.0.0-rc1", "v2.0.0-rc1"],
  ];
  for (const [input, tag] of cases) {
    const got = resolveBaseURL(input);
    assert.equal(got.tag, tag, input);
    assert.equal(
      got.baseURL,
      `https://github.com/aflock-ai/cilock-action/releases/download/${tag}`,
      input,
    );
  }
});

test("resolveBaseURL falls back to latest for refs without their own release", () => {
  const cases = [
    "latest",
    "", // version input absent and GITHUB_ACTION_REF unset (local actions)
    "main",
    "dev",
    "v1", // floating major alias tag — git tag only, no GitHub Release
    "v2",
    "1",
    "v1.0", // major.minor alias — also release-less
    "692973e3d937129bcbf40652eb9f2f61becf3332", // full commit-SHA pin
    "deadbeef", // abbreviated sha
  ];
  for (const input of cases) {
    const got = resolveBaseURL(input);
    assert.equal(got.tag, "latest", JSON.stringify(input));
    assert.equal(
      got.baseURL,
      "https://github.com/aflock-ai/cilock-action/releases/latest/download",
      JSON.stringify(input),
    );
  }
});

test("parseChecksums finds the asset digest in goreleaser checksums.txt", () => {
  const a = "a".repeat(64);
  const b = "B".repeat(64);
  const body = [
    `${a}  cilock-action_linux_amd64.tar.gz`,
    `${b}  cilock-action_darwin_arm64.tar.gz`,
    "",
  ].join("\n");

  assert.equal(parseChecksums(body, "cilock-action_linux_amd64.tar.gz"), a);
  // digest is normalized to lowercase
  assert.equal(
    parseChecksums(body, "cilock-action_darwin_arm64.tar.gz"),
    "b".repeat(64),
  );
});

test("parseChecksums throws when the asset has no entry", () => {
  const body = `${"a".repeat(64)}  cilock-action_linux_amd64.tar.gz\n`;
  assert.throws(
    () => parseChecksums(body, "cilock-action_linux_arm64.tar.gz"),
    /no entry for cilock-action_linux_arm64\.tar\.gz/,
  );
  assert.throws(() => parseChecksums("", "x.tar.gz"), /no entry/);
  // a tampered/garbled line must not match
  assert.throws(
    () => parseChecksums("nothex  x.tar.gz", "x.tar.gz"),
    /no entry/,
  );
});

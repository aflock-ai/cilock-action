const core = require("@actions/core");
const tc = require("@actions/tool-cache");
const exec = require("@actions/exec");
const os = require("os");
const path = require("path");
const https = require("https");

const REPO = "aflock-ai/cilock-action";

// Resolve `ref` to a release tag.
//
// If `ref` is a 40-char hex commit SHA, look up the tag at that commit via
// the GitHub API. This lets consumers SHA-pin the action (`uses:
// owner/repo@<sha>`) — the standard supply-chain hygiene pattern — without
// 404'ing the release-asset download (which is hosted under /releases/
// download/<tag-name>/, not /releases/download/v<sha>/).
//
// If `ref` is "latest", a tag name (v1.0.1), or anything else non-SHA-shaped,
// it's returned unchanged.
async function resolveRefToTag(ref) {
  if (ref === "latest") return ref;
  if (!/^[0-9a-f]{40}$/i.test(ref)) return ref;

  const tags = await ghApi(`/repos/${REPO}/tags?per_page=100`);
  const match = tags.find((t) => t.commit && t.commit.sha === ref.toLowerCase());
  if (!match) {
    throw new Error(
      `cilock-action ref ${ref} is a 40-char SHA but does not match any ` +
        `published release tag in ${REPO}. Pin to a v* tag or pass the ` +
        `'version' input.`,
    );
  }
  core.info(`Resolved SHA ${ref} → tag ${match.name}`);
  return match.name;
}

// Lightweight authenticated GET against api.github.com.
// Uses GITHUB_TOKEN when present (which is true inside Actions runners).
function ghApi(pathSuffix) {
  return new Promise((resolve, reject) => {
    const headers = {
      "User-Agent": "cilock-action-shim",
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    const token = process.env.GITHUB_TOKEN;
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const req = https.request(
      {
        host: "api.github.com",
        path: pathSuffix,
        method: "GET",
        headers,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(
              new Error(
                `GitHub API ${pathSuffix} returned HTTP ${res.statusCode}: ${body.slice(0, 200)}`,
              ),
            );
          }
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(new Error(`GitHub API ${pathSuffix} returned non-JSON: ${body.slice(0, 200)}`));
          }
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function run() {
  try {
    const rawVersion =
      core.getInput("version") || process.env.GITHUB_ACTION_REF || "latest";
    // 40-char SHA refs (the supply-chain-pin pattern) — resolve to their
    // release tag before the download URL is constructed.
    const resolved = await resolveRefToTag(rawVersion);
    // Branch refs (main, dev) aren't release tags — use latest release
    const version = /^v?\d+/.test(resolved) ? resolved : "latest";
    const customURL = core.getInput("cilock-binary-url");

    let binaryPath;
    if (customURL) {
      const downloaded = await tc.downloadTool(customURL);
      binaryPath = downloaded;
    } else {
      const platform = os.platform(); // linux, darwin, win32
      const arch = os.arch(); // x64, arm64

      const goOS = platform === "win32" ? "windows" : platform;
      const goArch = arch === "x64" ? "amd64" : arch;

      const tag = version === "latest" ? "latest" : `v${version.replace(/^v/, "")}`;
      const baseURL = `https://github.com/${REPO}/releases/${tag === "latest" ? "latest/download" : `download/${tag}`}`;

      // Try tarball first (goreleaser output), fall back to raw binary
      const ext = platform === "win32" ? ".zip" : ".tar.gz";
      const archiveURL = `${baseURL}/cilock-action_${goOS}_${goArch}${ext}`;

      core.info(`Downloading cilock-action from ${archiveURL}`);
      const downloaded = await tc.downloadTool(archiveURL);

      // Extract archive
      let extractedDir;
      if (ext === ".zip") {
        extractedDir = await tc.extractZip(downloaded);
      } else {
        extractedDir = await tc.extractTar(downloaded);
      }

      const binaryName = platform === "win32" ? "cilock-action.exe" : "cilock-action";
      binaryPath = path.join(extractedDir, binaryName);
    }

    // Make executable
    await exec.exec("chmod", ["+x", binaryPath]);

    // Run the Go binary — it reads INPUT_* env vars directly
    const exitCode = await exec.exec(binaryPath, [], {
      ignoreReturnCode: true,
    });

    if (exitCode !== 0) {
      core.setFailed(`cilock-action exited with code ${exitCode}`);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();

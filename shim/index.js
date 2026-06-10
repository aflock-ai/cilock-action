const core = require("@actions/core");
const tc = require("@actions/tool-cache");
const exec = require("@actions/exec");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { resolveAsset, resolveBaseURL, parseChecksums } = require("./resolve");

async function run() {
  try {
    const rawVersion =
      core.getInput("version") || process.env.GITHUB_ACTION_REF || "latest";
    const customURL = core.getInput("cilock-binary-url");

    let binaryPath;
    if (customURL) {
      // Escape hatch: user-supplied binary. The user owns platform fit and
      // integrity (e.g. rookery-builder custom binaries).
      binaryPath = await tc.downloadTool(customURL);
    } else {
      // Fail fast with a clear message on unsupported runners (Windows,
      // exotic arches) instead of a 404 from a nonexistent release asset.
      const { assetName } = resolveAsset(process.platform, process.arch);
      const { tag, baseURL } = resolveBaseURL(rawVersion);

      const archiveURL = `${baseURL}/${assetName}`;
      core.info(`Downloading cilock-action ${tag} from ${archiveURL}`);
      const downloaded = await tc.downloadTool(archiveURL);

      // Verify sha256 against the checksums.txt published in the same release.
      const checksumsPath = await tc.downloadTool(`${baseURL}/checksums.txt`);
      const want = parseChecksums(
        fs.readFileSync(checksumsPath, "utf8"),
        assetName,
      );
      const got = crypto
        .createHash("sha256")
        .update(fs.readFileSync(downloaded))
        .digest("hex");
      if (got !== want) {
        throw new Error(
          `sha256 mismatch for ${assetName}: expected ${want}, got ${got}`,
        );
      }
      core.info(`sha256 verified: ${got}`);

      const extractedDir = await tc.extractTar(downloaded);
      binaryPath = path.join(extractedDir, "cilock-action");
    }

    // Make executable (supported runners are linux/darwin only)
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

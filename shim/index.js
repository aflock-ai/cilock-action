const core = require("@actions/core");
const tc = require("@actions/tool-cache");
const exec = require("@actions/exec");
const os = require("os");
const path = require("path");

async function run() {
  try {
    const rawVersion =
      core.getInput("version") || process.env.GITHUB_ACTION_REF || "latest";
    // Branch refs (main, dev) aren't release tags — use latest release
    const version = /^v?\d+/.test(rawVersion) ? rawVersion : "latest";
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
      const baseURL = `https://github.com/aflock-ai/cilock-action/releases/${tag === "latest" ? "latest/download" : `download/${tag}`}`;

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

const core = require("@actions/core");
const tc = require("@actions/tool-cache");
const exec = require("@actions/exec");
const os = require("os");
const path = require("path");

async function run() {
  try {
    const version =
      core.getInput("version") || process.env.GITHUB_ACTION_REF || "latest";
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
      const ext = platform === "win32" ? ".exe" : "";

      const tag = version === "latest" ? "latest" : `v${version.replace(/^v/, "")}`;
      const url = `https://github.com/aflock-ai/cilock-action/releases/${tag === "latest" ? "latest/download" : `download/${tag}`}/cilock-action_${goOS}_${goArch}${ext}`;

      core.info(`Downloading cilock-action from ${url}`);
      const downloaded = await tc.downloadTool(url);
      binaryPath = downloaded;
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

// Zero-dependency bootstrap shim for cilock-action.
//
// Responsibilities (deliberately minimal — the Go binary does the real
// work and reads its configuration from the INPUT_* env vars the runner
// sets automatically for a JS action):
//
//   1. Resolve the action ref to a release tag (SHA-pin → tag via the
//      GitHub API; "latest" / v-tags pass through).
//   2. Download the platform binary archive (following redirects).
//   3. Extract it, chmod +x, exec it. Inputs flow through INPUT_* env;
//      we never build a shell command line from user input.
//
// NO third-party packages: only Node built-ins. This is intentional —
// a supply-chain attestation tool must not carry an unaudited npm
// dependency tree in its own wrapper. Extraction shells out to `tar`
// (present on every GitHub-hosted runner, incl. Windows bsdtar), invoked
// with a fixed argv array — never a shell string.

"use strict";

const os = require("os");
const path = require("path");
const fs = require("fs");
const https = require("https");
const { spawnSync } = require("child_process");

const REPO = "aflock-ai/cilock-action";

// ── @actions/core replacements (workflow-command protocol) ──────────────
// Inputs arrive as INPUT_<NAME> (uppercased, spaces→underscores) — the
// runner sets these for JS actions. We read them as data, never eval.
function getInput(name) {
  const key = "INPUT_" + name.replace(/ /g, "_").toUpperCase();
  return (process.env[key] || "").trim();
}
function info(msg) {
  process.stdout.write(msg + "\n");
}
function setFailed(msg) {
  // ::error:: is the documented workflow command; no library needed.
  process.stdout.write("::error::" + String(msg).replace(/\r?\n/g, "%0A") + "\n");
  process.exitCode = 1;
}

// ── GitHub API GET (built-in https, follows the same auth as before) ────
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
      { host: "api.github.com", path: pathSuffix, method: "GET", headers },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(
              new Error(`GitHub API ${pathSuffix} returned HTTP ${res.statusCode}: ${body.slice(0, 200)}`),
            );
          }
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error(`GitHub API ${pathSuffix} returned non-JSON: ${body.slice(0, 200)}`));
          }
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

// Resolve a 40-char SHA ref to its release tag (supply-chain pin pattern);
// pass through "latest" and v-tags unchanged.
async function resolveRefToTag(ref) {
  if (ref === "latest") return ref;
  if (!/^[0-9a-f]{40}$/i.test(ref)) return ref;

  const tags = await ghApi(`/repos/${REPO}/tags?per_page=100`);
  const match = tags.find((t) => t.commit && t.commit.sha === ref.toLowerCase());
  if (!match) {
    throw new Error(
      `cilock-action ref ${ref} is a 40-char SHA but matches no published ` +
        `release tag in ${REPO}. Pin to a v* tag or pass the 'version' input.`,
    );
  }
  info(`Resolved SHA ${ref} → tag ${match.name}`);
  return match.name;
}

// Download a URL to a temp file, following 3xx redirects (GitHub release
// assets redirect to objects.githubusercontent.com). Returns the path.
function download(url, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 10) return reject(new Error("too many redirects"));
    https
      .get(url, { headers: { "User-Agent": "cilock-action-shim" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          const next = new URL(res.headers.location, url).toString();
          return resolve(download(next, depth + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`download ${url} returned HTTP ${res.statusCode}`));
        }
        const dest = path.join(
          fs.mkdtempSync(path.join(os.tmpdir(), "cilock-")),
          path.basename(new URL(url).pathname) || "download",
        );
        const out = fs.createWriteStream(dest);
        res.pipe(out);
        out.on("finish", () => out.close(() => resolve(dest)));
        out.on("error", reject);
      })
      .on("error", reject);
  });
}

// Extract a .tar.gz or .zip into a fresh dir using `tar` with a fixed
// argv (no shell). Windows ships bsdtar, which reads both formats.
function extract(archive) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cilock-x-"));
  const r = spawnSync("tar", ["-xf", archive, "-C", dir], { stdio: "inherit" });
  if (r.status !== 0) throw new Error(`tar extraction failed (exit ${r.status})`);
  return dir;
}

// prepareLinuxTracing best-effort enables cilock's fast in-kernel eBPF
// tracing path on Linux runners. Two steps, both non-fatal — if sudo is
// unavailable (e.g. a container: job) cilock falls back to ptrace+seccomp,
// which is slower but functionally equivalent:
//
//   1. Install the BPF rebuild toolchain (clang/llvm/libbpf-dev + bpftool).
//      cilock ships a prebuilt .bpf.o, but its CO-RE relocations are baked
//      against the build kernel's BTF; on Azure-flavored hosted-runner
//      kernels that can differ, so cilock rebuilds the object from embedded
//      source against /sys/kernel/btf/vmlinux — which needs these tools.
//   2. Grant CAP_BPF + CAP_PERFMON (NOT CAP_SYS_ADMIN) to the binary so it
//      can create BPF maps / attach kprobes without being root.
function prepareLinuxTracing(binaryPath) {
  const sudo = (args) =>
    spawnSync("sudo", ["-n", ...args], { stdio: ["ignore", "ignore", "inherit"] }).status;
  try {
    const base = sudo(["apt-get", "install", "-y", "-qq", "clang", "llvm", "libbpf-dev"]);
    let bpftool = sudo(["apt-get", "install", "-y", "-qq", "bpftool"]);
    if (bpftool !== 0) bpftool = sudo(["apt-get", "install", "-y", "-qq", "linux-tools-generic"]);
    info(
      base === 0 && bpftool === 0
        ? "Installed BPF rebuild toolchain — cilock can rebuild its eBPF object against this kernel if CO-RE fails"
        : "BPF rebuild toolchain install partial/failed — cilock will try the embedded object, else fall back to ptrace+seccomp",
    );
  } catch (e) {
    info(`BPF rebuild toolchain install skipped (${e.message}); ptrace fallback still works`);
  }
  try {
    const ok = sudo(["setcap", "cap_bpf,cap_perfmon+ep", binaryPath]) === 0;
    info(
      ok
        ? "Granted eBPF capabilities (CAP_BPF, CAP_PERFMON) — cilock will use the eBPF tracing path"
        : "Could not grant eBPF capabilities (no sudo / setcap denied) — cilock falls back to ptrace+seccomp",
    );
  } catch (e) {
    info(`setcap attempt failed (${e.message}); cilock will use ptrace+seccomp tracing`);
  }
}

// traceRequested reports whether the operator asked for command tracing.
function traceRequested() {
  return /^(1|true|yes|on)$/i.test(getInput("trace"));
}

// ebpfViable is a best-effort check for whether cilock's eBPF tracing can
// load on this kernel. eBPF + CO-RE needs kernel BTF (/sys/kernel/btf/vmlinux)
// and — empirically on hosted Azure-tuned runners — a 6.x kernel; 5.x runners
// (e.g. ubuntu-22.04's 5.15) fail CO-RE relocation even after a rebuild.
function ebpfViable() {
  if (!fs.existsSync("/sys/kernel/btf/vmlinux")) {
    return { ok: false, reason: "this kernel exposes no BTF (/sys/kernel/btf/vmlinux is absent)" };
  }
  const release = os.release(); // e.g. "6.8.0-1014-azure"
  const major = parseInt(release, 10) || 0;
  if (major < 6) {
    return { ok: false, reason: `kernel ${release} is older than 6.x, where hosted-runner eBPF/CO-RE is unreliable` };
  }
  return { ok: true, release };
}

// configureLinuxTracing picks the tracing backend before exec and tells the
// operator plainly what happened. eBPF where viable; otherwise auto-fall back
// to ptrace+seccomp (slower, same evidence) with a clear, actionable message.
// An explicit CILOCK_TRACE_MODE always wins (e.g. "ebpf" for fail-closed).
function configureLinuxTracing(binaryPath) {
  if (os.platform() !== "linux" || !traceRequested()) return;

  if (process.env.CILOCK_TRACE_MODE) {
    info(`Tracing backend pinned by CILOCK_TRACE_MODE=${process.env.CILOCK_TRACE_MODE}`);
    if (process.env.CILOCK_TRACE_MODE === "ebpf") prepareLinuxTracing(binaryPath);
    return;
  }

  const v = ebpfViable();
  if (v.ok) {
    prepareLinuxTracing(binaryPath);
    return;
  }
  // Kernel can't do eBPF here — degrade to ptrace instead of hard-failing.
  process.env.CILOCK_TRACE_MODE = "ptrace";
  info(
    "::warning::eBPF tracing is unavailable on this runner: " + v.reason + ". " +
      "Falling back to ptrace+seccomp tracing — it records the SAME evidence (process " +
      "tree, file accesses, digests) but is SLOWER, noticeably so for build-heavy commands. " +
      "For the fast eBPF path, use a kernel 6.x+ runner (e.g. ubuntu-24.04). To force a " +
      "backend, set CILOCK_TRACE_MODE=ebpf (fail-closed) or =ptrace.",
  );
}

async function run() {
  try {
    const rawVersion = getInput("version") || process.env.GITHUB_ACTION_REF || "latest";
    const resolved = await resolveRefToTag(rawVersion);
    // Branch refs (main, dev) aren't release tags — fall back to latest.
    const version = /^v?\d+/.test(resolved) ? resolved : "latest";
    const customURL = getInput("cilock-binary-url");

    let binaryPath;
    if (customURL) {
      binaryPath = await download(customURL);
    } else {
      const platform = os.platform(); // linux | darwin | win32
      const arch = os.arch(); // x64 | arm64
      const goOS = platform === "win32" ? "windows" : platform;
      const goArch = arch === "x64" ? "amd64" : arch;

      const tag = version === "latest" ? "latest" : `v${version.replace(/^v/, "")}`;
      const base = `https://github.com/${REPO}/releases/${tag === "latest" ? "latest/download" : `download/${tag}`}`;
      const ext = platform === "win32" ? ".zip" : ".tar.gz";
      const archiveURL = `${base}/cilock-action_${goOS}_${goArch}${ext}`;

      info(`Downloading cilock-action from ${archiveURL}`);
      const archive = await download(archiveURL);
      const dir = extract(archive);
      const binaryName = platform === "win32" ? "cilock-action.exe" : "cilock-action";
      binaryPath = path.join(dir, binaryName);
    }

    if (os.platform() !== "win32") fs.chmodSync(binaryPath, 0o755);

    // On Linux, pick the tracing backend: eBPF where the kernel supports it,
    // else an explicit ptrace+seccomp fallback with a clear operator message.
    configureLinuxTracing(binaryPath);

    // Exec the Go binary. argv is empty + no shell: the binary reads its
    // configuration from the INPUT_* env the runner already set. There is
    // no point at which user input becomes shell text.
    const r = spawnSync(binaryPath, [], { stdio: "inherit" });
    if (r.error) throw r.error;
    if (r.status !== 0) setFailed(`cilock-action exited with code ${r.status}`);
  } catch (error) {
    setFailed(error.message);
  }
}

run();

/**
 * Adversarial tests for the remote (SSH) network sandbox of patch 2
 * (`feat(codex-local): network sandbox on SSH execution targets`), written red after the
 * review of 9150f1222. Decisions under test:
 *
 * 1. Read-only root. Every SSH command sources /etc/profile, ~/.profile, ~/.bash_profile or
 *    ~/.bashrc and ~/.zprofile outside the sandbox (ssh.ts:1313-1316). With `--bind / /`
 *    (local-process-sandbox.ts:410) the confined Codex could plant commands in those files that
 *    later setup/cleanup run unconfined. On remote targets the argv must `--ro-bind / /` and bind
 *    read-write only the run's workspace (cwd) and the run's CODEX_HOME (`managedPaths` rw); the
 *    proxy runtime dir must not be writable from inside.
 * 2. Controller-side proxy pid. Cleanup must not trust a pid file in a directory the confined
 *    process can write (execution-target.ts:876). Contract: the setup prints the background
 *    proxy pid (`$!`) as the last line of its stdout; the controller keeps it; cleanup kills only
 *    that pid, after checking `/proc/<pid>/cmdline` names the run's `proxy.mjs`.
 * 3. Fail closed: if the proxy socket is not ready, cleanup runs and nothing is spawned.
 */
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  runSshCommand: vi.fn(async (_spec: unknown, _command: string) => ({ stdout: "4242\n", stderr: "" })),
  runChildProcess: vi.fn(async () => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout: "",
    stderr: "",
    pid: 1,
    startedAt: new Date().toISOString(),
  })),
}));

vi.mock("./ssh.js", async () => {
  const actual = await vi.importActual<typeof import("./ssh.js")>("./ssh.js");
  return { ...actual, runSshCommand: mocks.runSshCommand };
});

vi.mock("./server-utils.js", async () => {
  const actual = await vi.importActual<typeof import("./server-utils.js")>("./server-utils.js");
  return { ...actual, runChildProcess: mocks.runChildProcess };
});

import { runAdapterExecutionTargetProcess } from "./execution-target.js";
import { buildRemoteNetworkSandboxSpawnTarget } from "./local-process-sandbox.js";

const WORKSPACE = "/home/factory/workspaces/run-1";
const CODEX_HOME = `${WORKSPACE}/.paperclip-runtime/codex/home`;
const HOME = "/home/factory";

const SSH_TARGET = {
  kind: "remote" as const,
  transport: "ssh" as const,
  remoteCwd: WORKSPACE,
  spec: {
    host: "127.0.0.1",
    port: 2222,
    username: "factory",
    remoteWorkspacePath: "/home/factory/workspaces",
    remoteCwd: WORKSPACE,
    privateKey: "PRIVATE KEY",
    knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA",
    strictHostKeyChecking: true,
  },
};

const SANDBOX_OPTIONS = {
  workspaceDir: WORKSPACE,
  managedPaths: [{ path: CODEX_HOME, access: "rw" as const }],
  networkScope: "allowlist" as const,
  networkAllowlist: ["api.openai.com"],
  networkTrustedUrls: [],
  command: "bwrap",
};

/** Mount table after applying bwrap binds in order; later mounts win over earlier ones. */
function mounts(args: string[]): Array<{ dest: string; writable: boolean }> {
  const table: Array<{ dest: string; writable: boolean }> = [];
  for (let i = 0; i < args.length; i += 1) {
    const flag = args[i];
    if (["--bind", "--bind-try", "--dev-bind", "--dev-bind-try"].includes(flag)) {
      table.push({ dest: path.posix.resolve(args[i + 2]), writable: true });
      i += 2;
    } else if (["--ro-bind", "--ro-bind-try"].includes(flag)) {
      table.push({ dest: path.posix.resolve(args[i + 2]), writable: false });
      i += 2;
    } else if (flag === "--") {
      break;
    }
  }
  return table;
}

function writable(args: string[], candidate: string): boolean {
  const target = path.posix.resolve(candidate);
  let result = false;
  for (const mount of mounts(args)) {
    const covers = target === mount.dest || target.startsWith(mount.dest === "/" ? "/" : `${mount.dest}/`);
    if (covers) result = mount.writable;
  }
  return result;
}

function triples(args: string[], flag: string): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === "--") break;
    if (args[i] === flag) out.push(args.slice(i, i + 3));
  }
  return out;
}

describe("remote network sandbox argv (read-only root)", () => {
  const runtimeDir = "/tmp/pcp-net-fixture";

  function build(runtime = runtimeDir) {
    return buildRemoteNetworkSandboxSpawnTarget({
      executable: "codex",
      args: ["exec", "--json", "-"],
      cwd: WORKSPACE,
      runtimeDir: runtime,
      options: SANDBOX_OPTIONS,
    });
  }

  it("binds the root read-only, never read-write", () => {
    const { args } = build();
    expect(triples(args, "--bind")).not.toContainEqual(["--bind", "/", "/"]);
    expect(triples(args, "--ro-bind")).toContainEqual(["--ro-bind", "/", "/"]);
  });

  it("makes only the workspace and CODEX_HOME writable", () => {
    const { args } = build();
    const rw = mounts(args).filter((mount) => mount.writable).map((mount) => mount.dest);
    for (const dir of rw) expect([WORKSPACE, CODEX_HOME]).toContain(dir);
    expect(writable(args, `${WORKSPACE}/src/main.ts`)).toBe(true);
    expect(writable(args, `${CODEX_HOME}/config.toml`)).toBe(true);
  });

  it("keeps login dotfiles and system profiles outside every writable bind", () => {
    const { args } = build();
    for (const file of [
      "/etc/profile",
      "/etc/profile.d/zz-planted.sh",
      `${HOME}/.profile`,
      `${HOME}/.bash_profile`,
      `${HOME}/.bashrc`,
      `${HOME}/.zprofile`,
      `${HOME}/.ssh/authorized_keys`,
      HOME,
    ]) {
      expect({ file, writable: writable(args, file) }).toEqual({ file, writable: false });
    }
  });

  it("keeps the proxy runtime dir read-only from inside", () => {
    for (const runtime of [runtimeDir, `${WORKSPACE}/.paperclip-runtime/net`]) {
      const { args } = build(runtime);
      for (const file of ["proxy.mjs", "proxy.sock", "codex", "proxy.pid", "anything-new"]) {
        expect({ file: `${runtime}/${file}`, writable: writable(args, `${runtime}/${file}`) })
          .toEqual({ file: `${runtime}/${file}`, writable: false });
      }
    }
  });
});

describe("remote network sandbox lifecycle over SSH", () => {
  afterEach(() => {
    vi.clearAllMocks();
    mocks.runSshCommand.mockImplementation(async () => ({ stdout: "4242\n", stderr: "" }));
  });

  async function runOnce() {
    const logs: string[] = [];
    const outcome = await runAdapterExecutionTargetProcess("run-1", SSH_TARGET as never, "codex", ["exec", "-"], {
      cwd: WORKSPACE,
      env: {},
      timeoutSec: 30,
      graceSec: 5,
      onLog: async (_stream: string, chunk: string) => {
        logs.push(chunk);
      },
      localProcessSandbox: SANDBOX_OPTIONS,
    } as never).then(
      (result) => ({ result, error: null as unknown }),
      (error: unknown) => ({ result: null, error }),
    );
    const commands = mocks.runSshCommand.mock.calls.map((call) => String(call[1]));
    return { ...outcome, logs, commands };
  }

  it("captures the proxy pid on the controller instead of a pid file", async () => {
    const { commands } = await runOnce();
    expect(commands.length).toBeGreaterThanOrEqual(2);
    const [setup] = commands;
    expect(setup).toMatch(/echo\s+"?\$!"?\s*(\n|$)/);
    for (const command of commands) expect(command).not.toContain("proxy.pid");
  });

  it("cleanup kills only the captured pid after checking its cmdline", async () => {
    const { commands } = await runOnce();
    const cleanup = commands[commands.length - 1];
    expect(cleanup).not.toMatch(/cat\s+[^\n]*proxy\.pid/);
    expect(cleanup).toContain("/proc/4242/cmdline");
    expect(cleanup).toContain("proxy.mjs");
    expect(cleanup).toMatch(/kill\b[^\n]*\b4242\b/);
    expect(cleanup).not.toMatch(/kill\b[^\n]*\$\(/);
  });

  it("fails closed when the proxy socket is not ready: cleanup runs and nothing is spawned", async () => {
    mocks.runSshCommand.mockImplementationOnce(async () => {
      throw new Error("Remote Paperclip network proxy failed to start.");
    });
    const { result, error, commands } = await runOnce();
    expect(mocks.runChildProcess).not.toHaveBeenCalled();
    expect(error !== null || (result as { exitCode?: number } | null)?.exitCode !== 0).toBe(true);
    expect(commands.length).toBeGreaterThanOrEqual(2);
    const cleanup = commands[commands.length - 1];
    expect(cleanup).toMatch(/rm -rf/);
    expect(cleanup).not.toContain("proxy.pid");
  });
});

/**
 * Re-review of 796f09775 (HIGH): the setup checks that writable paths do not contain HOME, but
 * not that a protected file is an alias INTO a writable path (execution-target.ts:~918). Case:
 * `~/.bashrc` is an existing symlink to a file in the workspace, so the confined agent edits it
 * and the next SSH command sources it unconfined (ssh.ts:1313-1316). Decision: the setup
 * canonicalises `/etc/profile`, `/etc/profile.d/*`, `~/.profile`, `~/.bash_profile`, `~/.bashrc`,
 * `~/.zprofile` and `~/.ssh/*` and refuses when any canonical target lies under a writable bind
 * (workspace or CODEX_HOME).
 *
 * The generated setup is run for real with `sh`, HOME in a temp dir, and stub `bwrap`/`node` on
 * PATH; the stub `node` records each call, so "refused before any file is written" means exit != 0
 * with no `node` call.
 */
describe("remote setup refuses login-profile aliases into writable paths", () => {
  afterEach(() => {
    vi.clearAllMocks();
    mocks.runSshCommand.mockImplementation(async () => ({ stdout: "4242\n", stderr: "" }));
  });

  async function setupScriptFor(workspace: string, codexHome: string): Promise<string> {
    mocks.runSshCommand.mockImplementation(async () => ({ stdout: "4242\n", stderr: "" }));
    await runAdapterExecutionTargetProcess(
      "run-alias",
      { ...SSH_TARGET, remoteCwd: workspace, spec: { ...SSH_TARGET.spec, remoteCwd: workspace } } as never,
      "codex",
      ["exec", "-"],
      {
        cwd: workspace,
        env: {},
        timeoutSec: 30,
        graceSec: 5,
        onLog: async () => {},
        localProcessSandbox: { ...SANDBOX_OPTIONS, workspaceDir: workspace, managedPaths: [{ path: codexHome, access: "rw" }] },
      } as never,
    ).catch(() => undefined);
    return String(mocks.runSshCommand.mock.calls[0]?.[1] ?? "");
  }

  async function runSetup(
    alias: { file: string; into: "workspace" | "codexHome" | null },
    extra?: (dirs: { root: string; home: string; workspace: string; codexHome: string }) => Promise<void>,
  ) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "pcp-alias-"));
    try {
      const home = path.join(root, "home");
      const workspace = path.join(root, "work", "run-1");
      const codexHome = path.join(workspace, ".paperclip-runtime", "codex", "home");
      const bin = path.join(root, "bin");
      const nodeLog = path.join(root, "node-calls.log");
      await fs.mkdir(path.join(home, ".ssh"), { recursive: true });
      await fs.mkdir(codexHome, { recursive: true });
      await fs.mkdir(bin, { recursive: true });
      await fs.writeFile(path.join(bin, "bwrap"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      await fs.writeFile(path.join(bin, "node"), `#!/bin/sh\necho "$@" >> '${nodeLog}'\nexit 0\n`, { mode: 0o755 });
      for (const name of [".profile", ".bash_profile", ".zprofile"]) {
        await fs.writeFile(path.join(home, name), "# real profile\n");
      }
      await fs.writeFile(path.join(home, ".bashrc"), "# real bashrc\n");
      if (alias.into) {
        const targetDir = alias.into === "workspace" ? workspace : codexHome;
        const target = path.join(targetDir, "planted.sh");
        await fs.writeFile(target, "# agent-controlled\n");
        await fs.rm(path.join(home, alias.file), { force: true });
        await fs.symlink(target, path.join(home, alias.file));
      }
      await extra?.({ root, home, workspace, codexHome });
      const script = await setupScriptFor(workspace, codexHome);
      expect(script.length).toBeGreaterThan(0);
      const outcome = await new Promise<{ code: number; stderr: string }>((resolve) => {
        execFile("sh", ["-c", script], {
          env: { HOME: home, PATH: `${bin}:/usr/bin:/bin` },
          timeout: 20_000,
        }, (error, _stdout, stderr) => {
          resolve({ code: error ? (typeof error.code === "number" ? error.code : 1) : 0, stderr: String(stderr) });
        });
      });
      const nodeCalls = await fs.readFile(nodeLog, "utf8").catch(() => "");
      return { ...outcome, nodeCalls };
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }

  it.runIf(process.platform === "linux")("a clean home passes the checks (control)", async () => {
    const { nodeCalls } = await runSetup({ file: ".bashrc", into: null });
    expect(nodeCalls).not.toBe("");
  });

  for (const [file, into] of [
    [".bashrc", "workspace"],
    [".profile", "workspace"],
    [".bash_profile", "codexHome"],
    [".zprofile", "workspace"],
    [".ssh/authorized_keys", "workspace"],
    [".ssh/config", "codexHome"],
  ] as const) {
    it.runIf(process.platform === "linux")(`refuses ~/${file} symlinked into the ${into}`, async () => {
      const { code, nodeCalls } = await runSetup({ file, into });
      expect(code).not.toBe(0);
      expect(nodeCalls).toBe("");
    });
  }

  // Re-review of 3954d0600, decision 2: refuse when ANY hop of the chain is under a writable
  // path, not only the final target.
  it.runIf(process.platform === "linux")("refuses ~/.bashrc -> workspace/link -> safe file outside", async () => {
    const { code, nodeCalls } = await runSetup({ file: ".bashrc", into: null }, async ({ root, home, workspace }) => {
      const safe = path.join(root, "safe", "bashrc");
      await fs.mkdir(path.dirname(safe), { recursive: true });
      await fs.writeFile(safe, "# read-only target outside the sandbox\n");
      await fs.symlink(safe, path.join(workspace, "link"));
      await fs.rm(path.join(home, ".bashrc"), { force: true });
      await fs.symlink(path.join(workspace, "link"), path.join(home, ".bashrc"));
    });
    expect(code).not.toBe(0);
    expect(nodeCalls).toBe("");
  });

  it.runIf(process.platform === "linux")("refuses a two-hop chain through CODEX_HOME", async () => {
    const { code, nodeCalls } = await runSetup({ file: ".profile", into: null }, async ({ root, home, codexHome }) => {
      const safe = path.join(root, "safe", "profile");
      await fs.mkdir(path.dirname(safe), { recursive: true });
      await fs.writeFile(safe, "# safe\n");
      const outside = path.join(root, "hop");
      await fs.symlink(path.join(codexHome, "hop2"), outside);
      await fs.symlink(safe, path.join(codexHome, "hop2"));
      await fs.rm(path.join(home, ".profile"), { force: true });
      await fs.symlink(outside, path.join(home, ".profile"));
    });
    expect(code).not.toBe(0);
    expect(nodeCalls).toBe("");
  });

  it.runIf(process.platform === "linux")("accepts a chain that never touches a writable path (control)", async () => {
    const { nodeCalls } = await runSetup({ file: ".bashrc", into: null }, async ({ root, home }) => {
      const safe = path.join(root, "safe", "bashrc");
      await fs.mkdir(path.dirname(safe), { recursive: true });
      await fs.writeFile(safe, "# safe\n");
      await fs.symlink(safe, path.join(root, "hop"));
      await fs.rm(path.join(home, ".bashrc"), { force: true });
      await fs.symlink(path.join(root, "hop"), path.join(home, ".bashrc"));
    });
    expect(nodeCalls).not.toBe("");
  });

  // Re-review of 3954d0600, decision 1: the read-only re-bind only protects a regular file.
  it.runIf(process.platform === "linux")("refuses when the workspace .git/config is a symlink", async () => {
    const { code, nodeCalls } = await runSetup({ file: ".bashrc", into: null }, async ({ root, workspace }) => {
      await fs.mkdir(path.join(workspace, ".git", "hooks"), { recursive: true });
      const elsewhere = path.join(root, "elsewhere-config");
      await fs.writeFile(elsewhere, "[core]\n");
      await fs.symlink(elsewhere, path.join(workspace, ".git", "config"));
    });
    expect(code).not.toBe(0);
    expect(nodeCalls).toBe("");
  });

  it.runIf(process.platform === "linux")("accepts a regular .git/config (control)", async () => {
    const { nodeCalls } = await runSetup({ file: ".bashrc", into: null }, async ({ workspace }) => {
      await fs.mkdir(path.join(workspace, ".git", "hooks"), { recursive: true });
      await fs.writeFile(path.join(workspace, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n");
    });
    expect(nodeCalls).not.toBe("");
  });

  it("canonicalises the protected files", async () => {
    const script = await setupScriptFor("/home/factory/workspaces/run-1",
      "/home/factory/workspaces/run-1/.paperclip-runtime/codex/home");
    expect(script).toMatch(/realpath|readlink -f/);
    for (const name of ["/etc/profile", "/etc/profile.d", ".profile", ".bash_profile", ".bashrc", ".zprofile", ".ssh"]) {
      expect(script).toContain(name);
    }
  });
});

/**
 * Re-review of 3954d0600, decision 1: inside the remote sandbox the workspace's `.git/config`,
 * `.git/hooks` and `.git/config.worktree` (if present) are re-bound read-only AFTER the workspace
 * rw bind, so the agent cannot add `filter.*`, `include.path` or hooks that host-side git
 * (`ssh.ts:806` checkout/reset) would execute. `.git` objects/refs stay writable (agents commit).
 */
describe("remote sandbox keeps the repo config immutable", () => {
  const build = () => buildRemoteNetworkSandboxSpawnTarget({
    executable: "codex",
    args: ["exec", "-"],
    cwd: WORKSPACE,
    runtimeDir: "/tmp/pcp-net-fixture",
    options: SANDBOX_OPTIONS,
  });

  function indexOfBind(args: string[], flags: string[], dest: string): number {
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === "--") break;
      if (flags.includes(args[i]) && path.posix.resolve(args[i + 2] ?? "") === dest) return i;
    }
    return -1;
  }

  it("re-binds .git/config, .git/hooks and .git/config.worktree read-only after the workspace bind", () => {
    const { args } = build();
    const workspaceBind = indexOfBind(args, ["--bind", "--bind-try"], WORKSPACE);
    expect(workspaceBind).toBeGreaterThanOrEqual(0);
    for (const dest of [`${WORKSPACE}/.git/config`, `${WORKSPACE}/.git/hooks`, `${WORKSPACE}/.git/config.worktree`]) {
      const ro = indexOfBind(args, ["--ro-bind", "--ro-bind-try"], dest);
      expect({ dest, after: ro > workspaceBind }).toEqual({ dest, after: true });
    }
  });

  it("leaves objects and refs writable but config and hooks read-only", () => {
    const { args } = build();
    expect(writable(args, `${WORKSPACE}/.git/objects/ab/cdef`)).toBe(true);
    expect(writable(args, `${WORKSPACE}/.git/refs/heads/main`)).toBe(true);
    for (const file of [".git/config", ".git/hooks/post-checkout", ".git/hooks/pre-commit", ".git/config.worktree"]) {
      expect({ file, writable: writable(args, `${WORKSPACE}/${file}`) }).toEqual({ file, writable: false });
    }
  });
});

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
 * Fork review of ce523a92b, decision C: the agent sandbox no longer re-binds `.git/config`,
 * `.git/hooks` or `.git/config.worktree` read-only (so `git push -u` works inside). The class of
 * repo-controlled execution is closed on the host side instead: host-side git runs inside its own
 * bwrap and confined runs stop sourcing user dotfiles (see `ssh.confined-run.test.ts`).
 */
describe("agent sandbox leaves the repo config writable", () => {
  it("has no read-only re-bind under .git", () => {
    const { args } = buildRemoteNetworkSandboxSpawnTarget({
      executable: "codex",
      args: ["exec", "-"],
      cwd: WORKSPACE,
      runtimeDir: "/tmp/pcp-net-fixture",
      options: SANDBOX_OPTIONS,
    });
    const roDests: string[] = [];
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === "--") break;
      if (args[i] === "--ro-bind" || args[i] === "--ro-bind-try") roDests.push(path.posix.resolve(args[i + 2] ?? ""));
    }
    for (const dest of [".git/config", ".git/hooks", ".git/config.worktree"]) {
      expect(roDests).not.toContain(`${WORKSPACE}/${dest}`);
    }
    expect(writable(args, `${WORKSPACE}/.git/config`)).toBe(true);
  });
});

/**
 * Decision A, at the run-flow boundary: a run with a confinement scope marks its SSH spec
 * `confinedRun: true`, and every SSH command of the flow (setup, cleanup, spawn) uses it.
 */
describe("confined SSH runs mark every SSH command", () => {
  afterEach(() => {
    vi.clearAllMocks();
    mocks.runSshCommand.mockImplementation(async () => ({ stdout: "4242\n", stderr: "" }));
  });

  it("setup, cleanup and spawn carry confinedRun", async () => {
    await runAdapterExecutionTargetProcess("run-mark", SSH_TARGET as never, "codex", ["exec", "-"], {
      cwd: WORKSPACE, env: {}, timeoutSec: 30, graceSec: 5, onLog: async () => {},
      localProcessSandbox: SANDBOX_OPTIONS,
    } as never).catch(() => undefined);
    expect(mocks.runSshCommand.mock.calls.length).toBeGreaterThanOrEqual(2);
    for (const call of mocks.runSshCommand.mock.calls) {
      expect((call[0] as { confinedRun?: boolean }).confinedRun).toBe(true);
    }
    const options = (mocks.runChildProcess.mock.calls[0] as unknown as [string, string, string[], {
      remoteExecution?: { confinedRun?: boolean } | null;
    }])[3];
    expect(options.remoteExecution?.confinedRun).toBe(true);
  });

  it("an unconfined SSH run keeps today's spec", async () => {
    await runAdapterExecutionTargetProcess("run-plain", SSH_TARGET as never, "codex", ["exec", "-"], {
      cwd: WORKSPACE, env: {}, timeoutSec: 30, graceSec: 5, onLog: async () => {},
    } as never).catch(() => undefined);
    const options = (mocks.runChildProcess.mock.calls[0] as unknown as [string, string, string[], {
      remoteExecution?: { confinedRun?: boolean } | null;
    }])[3];
    expect(options.remoteExecution?.confinedRun).not.toBe(true);
  });
});

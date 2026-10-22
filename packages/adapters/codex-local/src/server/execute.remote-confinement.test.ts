/**
 * ATDD (red) for the Factory v7 story 2.9 — confinement on remote execution targets.
 *
 * Patch 1 (`fix(codex-local): refuse confinement on remote execution targets`): a CLI-engine
 * run that asks for `filesystemScope` or `networkScope` on a remote target the adapter cannot
 * confine must fail before any remote preparation or spawn, shaped like
 * `adapter_engine_unavailable` (execute.ts:574-585) and the ACP refusal (acp.ts:104-108):
 * `exitCode: 1`, `errorCode: "codex_remote_confinement_unsupported"`,
 * `resultJson.executionRecovery = { kind: "bootstrap", providerWorkStarted: false }`.
 *
 * Patch 2 (`feat(codex-local): network sandbox on SSH execution targets`): on `transport: "ssh"`
 * a `networkScope` run is no longer refused; the remote command is wrapped in Bubblewrap with
 * `--unshare-net` (the allowlist proxy runs on the target) and the
 * `[paperclip] Confining Codex with … scope.` line is logged. `filesystemScope` on SSH and any
 * confinement on `transport: "sandbox"` stay refused.
 *
 * The "SSH + networkScope refused" row of the plan holds only between patch 1 and patch 2, so
 * this file asserts the end state (refused on sandbox transport and for filesystemScope on SSH;
 * confined on SSH for networkScope).
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  runChildProcess: vi.fn(async () => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout: "",
    stderr: "",
    pid: 123,
    startedAt: new Date().toISOString(),
  })),
  ensureCommandResolvable: vi.fn(async () => undefined),
  resolveCommandForLogs: vi.fn(async () => "/usr/bin/codex"),
  prepareWorkspaceForSshExecution: vi.fn(async () => ({ gitBacked: false })),
  restoreWorkspaceFromSshExecution: vi.fn(async () => undefined),
  runSshCommand: vi.fn(async () => ({ stdout: Buffer.from("{}").toString("base64"), stderr: "" })),
  syncDirectoryToSsh: vi.fn(async () => undefined),
  startAdapterExecutionTargetPaperclipBridge: vi.fn(async () => ({
    env: {
      PAPERCLIP_API_URL: "http://127.0.0.1:4310",
      PAPERCLIP_API_KEY: "bridge-token",
      PAPERCLIP_API_BRIDGE_MODE: "queue_v1",
    },
    stop: async () => {},
  })),
  prepareAdapterExecutionTargetRuntime: vi.fn(async () => ({
    target: { kind: "remote", transport: "sandbox", remoteCwd: "/sandbox/workspace" },
    workspaceRemoteDir: "/sandbox/workspace",
    runtimeRootDir: "/sandbox/.paperclip-runtime",
    assetDirs: { home: "/sandbox/.paperclip-runtime/codex/home" },
    restoreWorkspace: vi.fn(async () => undefined),
  })),
  runAdapterExecutionTargetProcess: vi.fn(async () => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout: "",
    stderr: "",
    pid: 123,
    startedAt: new Date().toISOString(),
  })),
  runAdapterExecutionTargetShellCommand: vi.fn(async () => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout: "",
    stderr: "",
    pid: null,
    startedAt: new Date().toISOString(),
  })),
  ensureAdapterExecutionTargetCommandResolvable: vi.fn(async () => undefined),
  ensureAdapterExecutionTargetRuntimeCommandInstalled: vi.fn(async () => undefined),
  resolveAdapterExecutionTargetCommandForLogs: vi.fn(async () => "/usr/bin/codex"),
}));

vi.mock("@paperclipai/adapter-utils/server-utils", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/server-utils")>(
    "@paperclipai/adapter-utils/server-utils",
  );
  return {
    ...actual,
    ensureCommandResolvable: mocks.ensureCommandResolvable,
    resolveCommandForLogs: mocks.resolveCommandForLogs,
    runChildProcess: mocks.runChildProcess,
  };
});

vi.mock("@paperclipai/adapter-utils/ssh", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/ssh")>(
    "@paperclipai/adapter-utils/ssh",
  );
  return {
    ...actual,
    prepareWorkspaceForSshExecution: mocks.prepareWorkspaceForSshExecution,
    restoreWorkspaceFromSshExecution: mocks.restoreWorkspaceFromSshExecution,
    runSshCommand: mocks.runSshCommand,
    syncDirectoryToSsh: mocks.syncDirectoryToSsh,
  };
});

vi.mock("@paperclipai/adapter-utils/execution-target", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/execution-target")>(
    "@paperclipai/adapter-utils/execution-target",
  );
  return {
    ...actual,
    startAdapterExecutionTargetPaperclipBridge: mocks.startAdapterExecutionTargetPaperclipBridge,
    prepareAdapterExecutionTargetRuntime: mocks.prepareAdapterExecutionTargetRuntime,
    // Only the sandbox transport is faked; local and SSH go through the real runner, which
    // ends in the mocked runChildProcess (the fixture of execute.remote.test.ts).
    runAdapterExecutionTargetProcess: vi.fn((...args: Parameters<typeof actual.runAdapterExecutionTargetProcess>) => {
      const target = args[1] as { transport?: string } | null | undefined;
      return target?.transport === "sandbox"
        ? mocks.runAdapterExecutionTargetProcess(...(args as []))
        : actual.runAdapterExecutionTargetProcess(...args);
    }),
    runAdapterExecutionTargetShellCommand: mocks.runAdapterExecutionTargetShellCommand,
    ensureAdapterExecutionTargetCommandResolvable: mocks.ensureAdapterExecutionTargetCommandResolvable,
    ensureAdapterExecutionTargetRuntimeCommandInstalled: mocks.ensureAdapterExecutionTargetRuntimeCommandInstalled,
    resolveAdapterExecutionTargetCommandForLogs: mocks.resolveAdapterExecutionTargetCommandForLogs,
  };
});

import { execute } from "./execute.js";

const SSH_SPEC = {
  host: "127.0.0.1",
  port: 2222,
  username: "fixture",
  remoteWorkspacePath: "/remote/workspace",
  remoteCwd: "/remote/workspace",
  privateKey: "PRIVATE KEY",
  knownHosts: "[127.0.0.1]:2222 ssh-ed25519 AAAA",
  strictHostKeyChecking: true,
};

type Target = "local" | "ssh" | "sandbox";

describe("codex confinement on remote execution targets", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    vi.clearAllMocks();
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (dir) await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function run(target: Target, scopes: Record<string, unknown>) {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-confine-"));
    cleanupDirs.push(rootDir);
    const workspaceDir = path.join(rootDir, "workspace");
    const codexHomeDir = path.join(rootDir, "codex-home");
    await mkdir(workspaceDir, { recursive: true });
    await mkdir(codexHomeDir, { recursive: true });
    await writeFile(path.join(codexHomeDir, "auth.json"), "{}", "utf8");
    const logs: Array<{ stream: string; chunk: string }> = [];
    const executionTarget =
      target === "ssh"
        ? { kind: "remote", transport: "ssh", remoteCwd: "/remote/workspace", spec: SSH_SPEC }
        : target === "sandbox"
          ? {
              kind: "remote",
              transport: "sandbox",
              providerKey: "fixture",
              remoteCwd: "/workspace",
              runner: { execute: vi.fn() },
            }
          : undefined;
    const result = await execute({
      runId: "run-confine",
      agent: {
        id: "agent-1",
        companyId: "company-1",
        name: "CodexCoder",
        adapterType: "codex_local",
        adapterConfig: {},
      },
      runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
      config: {
        engine: "cli",
        command: "codex",
        cwd: workspaceDir,
        env: { CODEX_HOME: codexHomeDir },
        ...scopes,
      },
      context: { paperclipWorkspace: { cwd: workspaceDir, source: "project_primary" } },
      ...(executionTarget ? { executionTarget } : {}),
      onLog: async (stream: string, chunk: string) => {
        logs.push({ stream, chunk });
      },
    } as never);
    return { result, logs };
  }

  function expectRefusedBeforeAnyRemoteWork(
    outcome: Awaited<ReturnType<typeof run>>,
  ) {
    const { result, logs } = outcome;
    expect(result.exitCode).toBe(1);
    expect(result.errorCode).toBe("codex_remote_confinement_unsupported");
    expect(typeof result.errorMessage).toBe("string");
    expect((result.resultJson as Record<string, unknown> | undefined)?.executionRecovery).toEqual({
      kind: "bootstrap",
      providerWorkStarted: false,
    });
    for (const mock of [
      mocks.prepareWorkspaceForSshExecution,
      mocks.syncDirectoryToSsh,
      mocks.runSshCommand,
      mocks.runChildProcess,
      mocks.startAdapterExecutionTargetPaperclipBridge,
      mocks.prepareAdapterExecutionTargetRuntime,
      mocks.runAdapterExecutionTargetProcess,
      mocks.runAdapterExecutionTargetShellCommand,
    ]) {
      expect(mock).not.toHaveBeenCalled();
    }
    expect(logs.some((entry) => entry.chunk.includes("Confining Codex"))).toBe(false);
  }

  it("refuses filesystemScope on an SSH target before remote preparation", async () => {
    expectRefusedBeforeAnyRemoteWork(await run("ssh", { filesystemScope: "workspace" }));
  });

  it("refuses filesystemScope combined with networkScope on an SSH target", async () => {
    expectRefusedBeforeAnyRemoteWork(
      await run("ssh", {
        filesystemScope: "workspace",
        networkScope: "allowlist",
        networkAllowlist: ["api.openai.com"],
      }),
    );
  });

  it("refuses networkScope on a sandbox transport target", async () => {
    expectRefusedBeforeAnyRemoteWork(
      await run("sandbox", { networkScope: "allowlist", networkAllowlist: ["api.openai.com"] }),
    );
  });

  it("refuses filesystemScope on a sandbox transport target", async () => {
    expectRefusedBeforeAnyRemoteWork(await run("sandbox", { filesystemScope: "workspace" }));
  });

  it("does not refuse remote runs without confinement", async () => {
    const { result } = await run("ssh", {});
    expect(result.errorCode).not.toBe("codex_remote_confinement_unsupported");
    expect(mocks.runChildProcess).toHaveBeenCalledTimes(1);
  });

  it("keeps local confinement unchanged", async () => {
    const { result, logs } = await run("local", {
      networkScope: "allowlist",
      networkAllowlist: ["api.openai.com"],
    });
    expect(result.errorCode).not.toBe("codex_remote_confinement_unsupported");
    expect(mocks.runChildProcess).toHaveBeenCalledTimes(1);
    const options = (mocks.runChildProcess.mock.calls[0] as unknown as [
      string,
      string,
      string[],
      { localProcessSandbox?: { networkScope?: string; networkAllowlist?: string[] } | null },
    ])[3];
    expect(options.localProcessSandbox?.networkScope).toBe("allowlist");
    expect(options.localProcessSandbox?.networkAllowlist).toEqual(["api.openai.com"]);
    expect(logs).toContainEqual({
      stream: "stdout",
      chunk: "[paperclip] Confining Codex with allowlist network scope.\n",
    });
  });

  it("confines networkScope on an SSH target with Bubblewrap and logs the Confining line", async () => {
    const { result, logs } = await run("ssh", {
      networkScope: "allowlist",
      networkAllowlist: ["api.openai.com"],
    });
    expect(result.errorCode).not.toBe("codex_remote_confinement_unsupported");
    expect(mocks.runChildProcess).toHaveBeenCalledTimes(1);
    const call = mocks.runChildProcess.mock.calls[0] as unknown as [
      string,
      string,
      string[],
      { remoteExecution?: unknown },
    ];
    expect(call[3].remoteExecution).toBeTruthy();
    const argv = [call[1], ...call[2]];
    expect(path.basename(argv[0] ?? "")).toBe("bwrap");
    expect(argv).toContain("--unshare-net");
    const separator = argv.indexOf("--");
    expect(separator).toBeGreaterThan(0);
    expect(path.basename(argv[separator + 1] ?? "")).toBe("codex");
    expect(logs).toContainEqual({
      stream: "stdout",
      chunk: "[paperclip] Confining Codex with allowlist network scope.\n",
    });
  });
});

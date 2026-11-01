import childProcess, { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildLocalProcessSandboxSpawnTarget,
  parseLocalProcessFilesystemScope,
  parseLocalProcessNetworkAllowlist,
  parseLocalProcessNetworkScope,
  parseLocalProcessSandboxExtraPaths,
} from "./local-process-sandbox.js";
import { runChildProcess } from "./server-utils.js";

const cleanup: string[] = [];
const execFileAsync = promisify(execFile);

async function createGitWorktree() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-git-worktree-"));
  cleanup.push(root);
  const repository = path.join(root, "repository");
  const workspace = path.join(root, "workspace");
  const commonDir = path.join(repository, ".git");
  const gitDir = path.join(commonDir, "worktrees", "workspace");
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
  await execFileAsync("git", ["init", "--initial-branch=main", repository], { env });
  await execFileAsync("git", ["-C", repository, "-c", "user.name=Test", "-c", "user.email=test@example.com",
    "commit", "--allow-empty", "-m", "Initial"], { env });
  await execFileAsync("git", ["-C", repository, "worktree", "add", "-b", "own", workspace], { env });
  await fs.mkdir(path.join(commonDir, "hooks"), { recursive: true });
  return { repository, workspace, commonDir, gitDir };
}

function worktreeSandbox(workspace: string) {
  return buildLocalProcessSandboxSpawnTarget({
    executable: process.execPath,
    args: ["-e", "process.exit(0)"],
    cwd: workspace,
    options: { workspaceDir: workspace, filesystemScope: "workspace" },
  });
}

function expectWorktreeMounts(
  args: string[], workspace: string, commonDir: string, gitDir: string,
  optionalReadOnlyPaths = [path.join(commonDir, "info")],
) {
  const mounts = args.flatMap((arg, index) =>
    arg === "--bind" || arg === "--ro-bind" ? [args.slice(index, index + 3)]
      : arg === "--tmpfs" ? [args.slice(index, index + 2)] : []);
  const start = mounts.findLastIndex((mount) => mount[1] === commonDir);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(mounts.slice(start)).toEqual([
    ["--ro-bind", commonDir, commonDir],
    ...["objects", "refs"].map((entry) => {
      const candidate = path.join(commonDir, entry);
      return ["--bind", candidate, candidate];
    }),
    ["--tmpfs", path.join(commonDir, "logs")],
    ["--bind", gitDir, gitDir],
    ["--tmpfs", path.join(gitDir, "logs")],
    ...[
      path.join(commonDir, "hooks"), path.join(commonDir, "config"),
      path.join(gitDir, "commondir"), path.join(gitDir, "gitdir"),
      ...optionalReadOnlyPaths, path.join(workspace, ".git"),
    ].map((candidate) => ["--ro-bind", candidate, candidate]),
  ]);
  const workspaceBind = mounts.findIndex((mount) => mount[0] === "--bind" && mount[1] === workspace);
  expect(workspaceBind).toBeGreaterThanOrEqual(0);
  expect(start).toBeGreaterThan(workspaceBind);
  expect(mounts).not.toContainEqual(["--bind", path.join(commonDir, "logs"), path.join(commonDir, "logs")]);
}

async function hashTree(root: string): Promise<string> {
  const hash = createHash("sha256");
  const visit = async (relative: string): Promise<void> => {
    const candidate = path.join(root, relative);
    const stat = await fs.lstat(candidate);
    const type = stat.isSymbolicLink() ? "symlink" : stat.isDirectory() ? "directory" : "file";
    const bytes = type === "symlink" ? Buffer.from(await fs.readlink(candidate))
      : type === "file" ? await fs.readFile(candidate) : Buffer.alloc(0);
    hash.update(JSON.stringify([relative, type, bytes.toString("base64")]));
    if (type === "directory") {
      for (const entry of (await fs.readdir(candidate)).sort()) await visit(path.join(relative, entry));
    }
  };
  await visit("");
  return hash.digest("hex");
}

async function withTmpDir<T>(tmpDir: string, run: () => Promise<T>): Promise<T> {
  const previousTmpDir = process.env.TMPDIR;
  process.env.TMPDIR = tmpDir;
  try {
    return await run();
  } finally {
    if (previousTmpDir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTmpDir;
  }
}

beforeEach(() => {
  // Real Git probes must not depend on the developer's system/global hooks.
  vi.stubEnv("GIT_CONFIG_NOSYSTEM", "1");
  vi.stubEnv("GIT_CONFIG_GLOBAL", "/dev/null");
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await Promise.all(cleanup.splice(0).map((candidate) => fs.rm(candidate, { recursive: true, force: true })));
});

describe("local process sandbox", () => {
  it.runIf(process.platform !== "linux")("rejects sandbox scopes on unsupported hosts", async () => {
    await expect(buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath, args: ["-e", "process.exit(0)"], cwd: process.cwd(),
      options: { workspaceDir: process.cwd(), networkScope: "deny" },
    })).rejects.toThrow("supported only on Linux");
  });

  it("parses read-only and writable extra paths", () => {
    expect(parseLocalProcessSandboxExtraPaths(["/opt/cache", { path: "/var/lib/tool", access: "rw" }])).toEqual([
      { path: "/opt/cache", access: "ro" },
      { path: "/var/lib/tool", access: "rw" },
    ]);
    expect(() => parseLocalProcessSandboxExtraPaths(["relative"])).toThrow("must be an absolute path");
  });

  it("parses network scopes and exact-host allowlists", () => {
    expect(parseLocalProcessFilesystemScope("workspace")).toBe("workspace");
    expect(parseLocalProcessFilesystemScope(undefined)).toBeNull();
    expect(() => parseLocalProcessFilesystemScope("workpace")).toThrow('filesystemScope must be "workspace"');
    expect(parseLocalProcessNetworkScope("deny")).toBe("deny");
    expect(parseLocalProcessNetworkScope("allowlist")).toBe("allowlist");
    expect(parseLocalProcessNetworkScope(undefined)).toBeNull();
    expect(parseLocalProcessNetworkAllowlist(["api.openai.com", "https://api.anthropic.com", "gateway.test:8443"]))
      .toEqual(["api.openai.com", "api.anthropic.com", "gateway.test:8443"]);
    expect(() => parseLocalProcessNetworkAllowlist(["*.example.com"])).toThrow("exact hostname");
    expect(() => parseLocalProcessNetworkScope("public")).toThrow('"deny" or "allowlist"');
  });

  it.runIf(process.platform === "linux")("describes every valid allowlist input when no proxy rules remain", async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-network-rules-"));
    cleanup.push(workspace);

    await expect(buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: workspace,
      options: {
        workspaceDir: workspace,
        networkScope: "allowlist",
        networkAllowlist: [],
        networkTrustedUrls: ["file:///not-a-network-target"],
      },
    })).rejects.toThrow("valid networkAllowlist hostname or HTTP(S) networkTrustedUrl");
  });

  it.runIf(process.platform === "linux")("builds a fresh-root bubblewrap command with workspace access", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-fs-sandbox-"));
    cleanup.push(root);
    const workspace = path.join(root, "workspace");
    const managedHome = path.join(root, "managed-home");
    await fs.mkdir(workspace);
    await fs.mkdir(managedHome);

    const target = await buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: ["-e", "console.log('ok')"],
      cwd: workspace,
      options: {
        workspaceDir: workspace,
        filesystemScope: "workspace",
        managedPaths: [{ path: managedHome, access: "rw" }],
        homeDir: managedHome,
      },
    });

    expect(target.command).toBe("bwrap");
    expect(target.args).toContain("--tmpfs");
    expect(target.args).toContain(workspace);
    expect(target.args).toContain(managedHome);
    expect(target.args.slice(-3)).toEqual([process.execPath, "-e", "console.log('ok')"]);
    for (const alias of ["/bin", "/sbin", "/lib", "/lib64"]) {
      const stat = await fs.lstat(alias).catch(() => null);
      if (!stat?.isSymbolicLink()) continue;
      const resolved = await fs.realpath(alias).catch(() => null);
      if (!resolved?.startsWith("/usr/")) continue;
      const link = target.args.findIndex((arg, index) =>
        arg === "--symlink" && target.args[index + 2] === alias);
      expect(link).toBeGreaterThan(-1);
      expect(target.args[link + 1]).toBe(await fs.readlink(alias));
      const mountTargets = target.args.flatMap((arg, index) =>
        arg === "--bind" || arg === "--ro-bind" ? [target.args[index + 2]] : []);
      expect(mountTargets).not.toContain(alias);
    }
  });

  it.runIf(process.platform === "linux").each(["absolute", "relative"])(
    "mounts worktree metadata in order with %s pointers",
    async (pointers) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      if (pointers === "relative") {
        await fs.writeFile(path.join(workspace, ".git"), `gitdir: ${path.relative(workspace, gitDir)}\n`);
      } else {
        await fs.writeFile(path.join(gitDir, "commondir"), `${commonDir}\n`);
      }
      const target = await worktreeSandbox(workspace);
      expectWorktreeMounts(target.args, workspace, commonDir, gitDir);
      expect(target.args.indexOf(workspace)).toBeLessThan(target.args.indexOf(commonDir));
    },
  );

  it.runIf(process.platform === "linux")("orders the complete allowlist before every read-only overlay", async () => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const modules = path.join(commonDir, "modules");
    const commonConfig = path.join(commonDir, "config.worktree");
    const ownConfig = path.join(gitDir, "config.worktree");
    await fs.mkdir(modules);
    await fs.writeFile(commonConfig, "# existing config\n");
    await fs.writeFile(ownConfig, "# existing config\n");
    const { args } = await worktreeSandbox(workspace);
    expectWorktreeMounts(args, workspace, commonDir, gitDir, [
      modules, commonConfig, ownConfig, path.join(commonDir, "info"),
    ]);
  });

  it.runIf(process.platform === "linux").each([
    [true, true], [true, false], [false, true], [false, false],
  ])("handles common logs present=%s and worktree logs present=%s", async (commonPresent, ownPresent) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const commonLogs = path.join(commonDir, "logs");
    const ownLogs = path.join(gitDir, "logs");
    if (!commonPresent) await fs.rm(commonLogs, { recursive: true });
    if (!ownPresent) await fs.rm(ownLogs, { recursive: true });
    const { args } = await worktreeSandbox(workspace);
    if (commonPresent) expectWorktreeMounts(args, workspace, commonDir, gitDir);
    else {
      expect(args).not.toContain(commonDir);
      expect(args).not.toContain(gitDir);
    }
    // Argument construction does not create mountpoints on the host.
    if (!commonPresent) await expect(fs.lstat(commonLogs)).rejects.toMatchObject({ code: "ENOENT" });
    if (!ownPresent) await expect(fs.lstat(ownLogs)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.runIf(process.platform === "linux").each(["symlink", "file"])(
    "rejects a worktree logs mountpoint that is a %s", async (kind) => {
      const { workspace, gitDir } = await createGitWorktree();
      const logs = path.join(gitDir, "logs");
      await fs.rename(logs, `${logs}-real`);
      if (kind === "symlink") await fs.symlink(`${logs}-real`, logs);
      else await fs.writeFile(logs, "not a directory");
      await expect(worktreeSandbox(workspace)).rejects.toThrow(`"${logs}" must exist`);
    },
  );

  it.runIf(process.platform === "linux")("preserves identical args for a normal checkout or no .git", async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-git-directory-"));
    cleanup.push(workspace);
    const baseline = await worktreeSandbox(workspace);
    await fs.mkdir(path.join(workspace, ".git"));
    expect((await worktreeSandbox(workspace)).args).toEqual(baseline.args);
  });

  it.runIf(process.platform === "linux").each([".git", "commondir", "gitdir"])(
    "protects the %s pointer after its covering writable bind",
    async (entry) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      const coveringPath = entry === ".git" ? workspace : gitDir;
      const pointer = path.join(coveringPath, entry);
      const { args } = await worktreeSandbox(workspace);
      expectWorktreeMounts(args, workspace, commonDir, gitDir);
      const coveringBind = args.findIndex((arg, index) =>
        arg === "--bind" && args[index + 1] === coveringPath && args[index + 2] === coveringPath);
      const pointerBind = args.lastIndexOf(pointer) - 2;
      expect(args.slice(coveringBind, coveringBind + 3)).toEqual(["--bind", coveringPath, coveringPath]);
      expect(args.slice(pointerBind, pointerBind + 3)).toEqual(["--ro-bind", pointer, pointer]);
      expect(pointerBind).toBeGreaterThan(coveringBind);
      expect(pointerBind).toBeGreaterThan(args.lastIndexOf(gitDir));
    },
  );

  it.runIf(process.platform === "linux").each([
    [".git", "missing"], [".git", "directory"], [".git", "symlink"],
    ["commondir", "missing"], ["commondir", "directory"], ["commondir", "symlink"],
    ["gitdir", "missing"], ["gitdir", "directory"], ["gitdir", "symlink"],
  ])("adds no worktree mounts for a %s pointer that is %s", async (entry, kind) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const gitFile = path.join(workspace, ".git");
    const contents = await fs.readFile(gitFile, "utf8");
    await fs.rm(gitFile);
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(gitFile, contents);
    const pointer = path.join(entry === ".git" ? workspace : gitDir, entry);
    await fs.rename(pointer, `${pointer}-real`);
    if (kind === "directory") await fs.mkdir(pointer);
    if (kind === "symlink") await fs.symlink(`${pointer}-real`, pointer);
    const { args } = await worktreeSandbox(workspace);
    expect(args).toEqual(baseline.args);
    expect(args).not.toContain(commonDir);
    expect(args).not.toContain(gitDir);
  });

  it.runIf(process.platform === "linux").each([".git", "commondir", "gitdir"])(
    "adds no mounts when the %s pointer is replaced before the final recheck",
    async (entry) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      const pointer = path.join(entry === ".git" ? workspace : gitDir, entry);
      const readFile = fs.readFile.bind(fs);
      let replaced = false;
      const initial = await fs.lstat(pointer, { bigint: true });
      // Config is read after discovery has recorded all three pointer identities.
      vi.spyOn(fs, "readFile").mockImplementation(async (candidate, options) => {
        const contents = await readFile(candidate, options);
        if (candidate === path.join(commonDir, "config") && !replaced) {
          await fs.rename(pointer, `${pointer}-old`);
          await fs.copyFile(`${pointer}-old`, pointer);
          replaced = true;
        }
        return contents;
      });
      const { args } = await worktreeSandbox(workspace);
      expect(replaced).toBe(true);
      expect((await fs.lstat(pointer, { bigint: true })).ino).not.toBe(initial.ino);
      expect(await readFile(pointer)).toEqual(await readFile(`${pointer}-old`));
      expect(args).not.toContain(commonDir);
      expect(args).not.toContain(gitDir);
      expect(args).not.toContain(pointer);
    },
  );

  it.runIf(process.platform === "linux").each(["dev", "ino", "size", "mtimeNs"] as const)(
    "adds no mounts when only file %s differs at the final recheck",
    async (field) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      const config = path.join(commonDir, "config");
      const lstat = fs.lstat.bind(fs);
      let checks = 0;
      vi.spyOn(fs, "lstat").mockImplementation(async (candidate, options) => {
        const stat = await lstat(candidate, options);
        if (candidate === config && ++checks === 2 && "mtimeNs" in stat) stat[field] += 1n;
        return stat;
      });
      const { args } = await worktreeSandbox(workspace);
      expect(checks).toBe(2);
      expect(args).not.toContain(commonDir);
      expect(args).not.toContain(gitDir);
    },
  );

  it.runIf(process.platform === "linux").each([".git", "commondir"])(
    "adds no mounts when the %s target changes despite unchanged stat metadata",
    async (entry) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      const pointer = path.join(entry === ".git" ? workspace : gitDir, entry);
      const readFile = fs.readFile.bind(fs);
      let reads = 0;
      vi.spyOn(fs, "readFile").mockImplementation(async (candidate, options) => {
        const contents = await readFile(candidate, options);
        // Preserve real stat results to isolate the pointer-content recheck.
        if (candidate === pointer && ++reads === 2) {
          return entry === ".git" ? `gitdir: ${commonDir}\n` : `${gitDir}\n`;
        }
        return contents;
      });
      const { args } = await worktreeSandbox(workspace);
      expect(reads).toBe(2);
      expect(args).not.toContain(commonDir);
      expect(args).not.toContain(gitDir);
    },
  );

  it.runIf(process.platform === "linux").each([
    ["extensions", "worktreeConfig", "true"],
    ["ExTeNsIoNs", "WorktreeConfig", "yes"],
    ["extensions", "worktreeconfig", "on"],
    ["extensions", "worktreeConfig", "1"],
    ["extensions", "worktreeConfig", "TrUe"],
    ["extensions", "worktreeConfig", '"yes"'],
    ["extensions", "worktreeConfig", null],
  ])("adds no worktree mounts for enabled [%s] %s = %s", async (section, key, value) => {
    const { workspace, commonDir } = await createGitWorktree();
    await fs.rm(path.join(workspace, ".git"));
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(path.join(workspace, ".git"), `gitdir: ${path.join(commonDir, "worktrees", "workspace")}\n`);
    await fs.appendFile(path.join(commonDir, "config"), `\n[${section}]\n\t${key}${value === null ? "" : ` = ${value}`}\n`);
    expect((await worktreeSandbox(workspace)).args).toEqual(baseline.args);
  });

  it.runIf(process.platform === "linux").each(["false", "no", "off", "0", "", "FaLsE", '"off"', '""'])(
    "mounts worktree metadata with worktreeConfig disabled by %j",
    async (value) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      await fs.appendFile(path.join(commonDir, "config"), `\n[ExTeNsIoNs] ; comment\n\tWorktreeConfig = ${value} # comment\n`);
      expectWorktreeMounts((await worktreeSandbox(workspace)).args, workspace, commonDir, gitDir);
    },
  );

  it.runIf(process.platform === "linux").each([
    "[core]\nhooksPath = x\n",
    "[core]\nhookspath=\n",
    "[CORE]\nHOOKSPATH\n",
    '[CoRe]\nHoOkSpAtH = "../hooks with spaces" # comment\n',
    '[core]\nhooksPath = ""\n',
    "[core] hooksPath = x\n",
    "[core]\nhooksPath = x\n[core]\nhooksPath =\n",
  ])("adds no mounts for configured core.hooksPath: %j", async (config) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const gitFile = path.join(workspace, ".git");
    await fs.rm(gitFile);
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(gitFile, `gitdir: ${gitDir}\n`);
    const configPath = path.join(commonDir, "config");
    await fs.appendFile(configPath, `\n${config}`);
    // These are real Git spellings, including inline sections and bare/empty keys.
    const parsed = await execFileAsync("git", ["config", "--file", configPath, "--get-all", "core.hooksPath"]);
    expect(parsed.stdout).toContain("\n");
    expect((await worktreeSandbox(workspace)).args).toEqual(baseline.args);
  });

  it.runIf(process.platform === "linux").each(["system", "global"])(
    "uses real Git to deny effective %s hooksPath, including empty values", async (scope) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      const config = path.join(path.dirname(workspace), `${scope}.gitconfig`);
      vi.stubEnv(scope === "global" ? "GIT_CONFIG_GLOBAL" : "GIT_CONFIG_SYSTEM", config);
      if (scope === "system") vi.stubEnv("GIT_CONFIG_NOSYSTEM", "0");
      for (const value of ["agent-hooks", ""]) {
        await fs.writeFile(config, `[core]\n\thooksPath = ${value}\n`);
        const parsed = await execFileAsync("git", ["config", "--get-all", "core.hooksPath"], { cwd: workspace });
        expect(parsed.stdout).toBe(`${value}\n`);
        const { args } = await worktreeSandbox(workspace);
        expect(args).not.toContain(commonDir);
        expect(args).not.toContain(gitDir);
      }
      await fs.writeFile(config, "# key unset\n");
      expectWorktreeMounts((await worktreeSandbox(workspace)).args, workspace, commonDir, gitDir);
    },
  );

  it.runIf(process.platform === "linux")("denies real worktree-level hooksPath", async () => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    await execFileAsync("git", ["config", "extensions.worktreeConfig", "true"], { cwd: workspace });
    await execFileAsync("git", ["config", "--worktree", "core.hooksPath", "agent-hooks"], { cwd: workspace });
    const parsed = await execFileAsync("git", ["config", "--get-all", "core.hooksPath"], { cwd: workspace });
    expect(parsed.stdout).toBe("agent-hooks\n");
    const { args } = await worktreeSandbox(workspace);
    expect(args).not.toContain(commonDir);
    expect(args).not.toContain(gitDir);
  });

  it.runIf(process.platform === "linux")("includes command-scope config from the runtime environment", async () => {
    const { workspace, commonDir } = await createGitWorktree();
    vi.stubEnv("GIT_CONFIG_COUNT", "1");
    vi.stubEnv("GIT_CONFIG_KEY_0", "core.hooksPath");
    vi.stubEnv("GIT_CONFIG_VALUE_0", "agent-hooks");
    expect((await worktreeSandbox(workspace)).args).not.toContain(commonDir);
  });

  it.runIf(process.platform === "linux").each(["GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_CONFIG"])(
    "denies mounts when %s could redirect the effective config query", async (key) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      vi.stubEnv(key, commonDir);
      const { args } = await worktreeSandbox(workspace);
      expect(args).not.toContain(commonDir);
      expect(args).not.toContain(gitDir);
    },
  );

  it.runIf(process.platform === "linux").each([
    ["empty successful output", null],
    ["exit 128", { code: 128 }],
    ["exit 2", { code: 2 }],
    ["spawn failure", { code: "ENOENT" }],
    ["timeout", { code: 1, killed: true, signal: "SIGKILL" }],
  ] as const)("denies mounts for an injected Git result: %s", async (_label, failure) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    // Mock the native subprocess boundary, without adding a caller-facing bypass.
    const probe = vi.spyOn(childProcess, "execFile").mockImplementationOnce((_file, _args, _options, callback) => {
      callback!(failure === null ? null : Object.assign(new Error("git failed"), failure), "", "");
      return {} as childProcess.ChildProcess;
    });
    const { args } = await worktreeSandbox(workspace);
    expect(probe).toHaveBeenCalledWith("git", ["config", "--get-all", "core.hooksPath"], {
      cwd: workspace, env: process.env, timeout: 3_000, killSignal: "SIGKILL",
    }, expect.any(Function));
    expect(args).not.toContain(commonDir);
    expect(args).not.toContain(gitDir);
  });

  it.runIf(process.platform === "linux")("denies mounts if spawning Git throws", async () => {
    const { workspace, commonDir } = await createGitWorktree();
    vi.spyOn(childProcess, "execFile").mockImplementationOnce(() => { throw new Error("spawn failed"); });
    expect((await worktreeSandbox(workspace)).args).not.toContain(commonDir);
  });

  it.runIf(process.platform === "linux")("kills a stalled config probe without blocking the event loop", async () => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const bin = path.join(path.dirname(workspace), "bin");
    await fs.mkdir(bin);
    await fs.writeFile(path.join(bin, "git"), "#!/bin/sh\nexec /bin/sleep 30\n", { mode: 0o755 });
    vi.stubEnv("PATH", bin);
    const probe = vi.spyOn(childProcess, "execFile");
    let settled = false;
    const pending = worktreeSandbox(workspace).finally(() => { settled = true; });
    // This timer can fire while execFile waits; SIGKILL bounds the actual child.
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(settled).toBe(false);
    const { args } = await pending;
    expect(probe.mock.results[0].value.signalCode).toBe("SIGKILL");
    expect(args).not.toContain(commonDir);
    expect(args).not.toContain(gitDir);
  }, 10_000);

  it.runIf(process.platform === "linux").each([
    '[core]\nhooksPath = "unterminated\n',
    "[core\nhooksPath = x\n",
    "[core]\nhooksPath = hook\\\ns\n",
    '[core]\nhooksPath = "bad\\qescape"\n',
    "[core]\nhooksPath = x\0\n",
    '[includeIf "gitdir:*"]\npath = hooks-config\n',
    "[core]\nhooksPath ? x\n",
  ])("adds no mounts for uncertain hooksPath config: %j", async (config) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    await fs.rm(path.join(workspace, ".git"));
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(path.join(workspace, ".git"), `gitdir: ${gitDir}\n`);
    await fs.appendFile(path.join(commonDir, "config"), `\n${config}`);
    expect((await worktreeSandbox(workspace)).args).toEqual(baseline.args);
  });

  it.runIf(process.platform === "linux").each([
    "[extensions]\nworktreeConfig = maybe\n",
    '[extensions]\nworktreeConfig = "false "\n',
    "[extensions\nworktreeConfig = true\n",
    '[core]\nvalue = "unterminated\n[extensions]\nworktreeConfig = false\n',
    "[extensions]\nworktreeConfig = fal\\\nse\n",
    "[extensions]\nworktreeConfig = false\0\n",
    "[include]\npath = other-config\n",
    '[includeIf "gitdir:*"]\npath = other-config\n',
    "[extensions]\nworktreeConfig = true\nworktreeConfig = false\n",
  ])("adds no worktree mounts when config is uncertain: %j", async (config) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    await fs.rm(path.join(workspace, ".git"));
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(path.join(workspace, ".git"), `gitdir: ${gitDir}\n`);
    await fs.appendFile(path.join(commonDir, "config"), `\n${config}`);
    expect((await worktreeSandbox(workspace)).args).toEqual(baseline.args);
  });

  it.runIf(process.platform === "linux").each([
    ["modules", true, "common"],
    ["config.worktree", false, "common"],
    ["config.worktree", false, "own"],
    ["info", true, "common"],
  ] as const)("protects %s (%s, %s) after its covering bind", async (entry, directory, location) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const coveringPath = location === "common" ? commonDir : gitDir;
    const protectedPath = path.join(coveringPath, entry);
    if (directory) await fs.mkdir(protectedPath, { recursive: true });
    else await fs.writeFile(protectedPath, "# existing config\n");
    const { args } = await worktreeSandbox(workspace);
    const coveringBind = args.lastIndexOf(coveringPath) - 2;
    const protectedBind = args.lastIndexOf(protectedPath) - 2;
    expect(args.slice(coveringBind, coveringBind + 3)).toEqual([
      location === "common" ? "--ro-bind" : "--bind", coveringPath, coveringPath,
    ]);
    expect(args.slice(protectedBind, protectedBind + 3)).toEqual(["--ro-bind", protectedPath, protectedPath]);
    expect(protectedBind).toBeGreaterThan(coveringBind);
    expect(protectedBind).toBeGreaterThan(args.lastIndexOf(gitDir));
  });

  it.runIf(process.platform === "linux")("skips absent optional protections without creating host paths", async () => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    await fs.rm(path.join(commonDir, "info"), { recursive: true });
    const { args } = await worktreeSandbox(workspace);
    expectWorktreeMounts(args, workspace, commonDir, gitDir, []);
    for (const candidate of [
      path.join(commonDir, "modules"), path.join(commonDir, "info"),
      path.join(commonDir, "config.worktree"), path.join(gitDir, "config.worktree"),
    ]) {
      expect(args).not.toContain(candidate);
      await expect(fs.lstat(candidate)).rejects.toMatchObject({ code: "ENOENT" });
    }
  });

  it.runIf(process.platform === "linux").each([
    ["modules", true, "common"],
    ["config.worktree", false, "common"],
    ["config.worktree", false, "own"],
    ["info", true, "common"],
  ] as const)("rejects symlinked or mistyped %s (%s, %s)", async (entry, directory, location) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const protectedPath = path.join(location === "common" ? commonDir : gitDir, entry);
    await fs.rm(protectedPath, { recursive: true, force: true });
    if (directory) await fs.mkdir(`${protectedPath}-real`);
    else await fs.writeFile(`${protectedPath}-real`, "# existing config\n");
    await fs.symlink(`${protectedPath}-real`, protectedPath);
    await expect(worktreeSandbox(workspace)).rejects.toThrow(`"${protectedPath}" must exist`);
    await fs.rm(protectedPath);
    if (directory) await fs.writeFile(protectedPath, "wrong type");
    else await fs.mkdir(protectedPath);
    await expect(worktreeSandbox(workspace)).rejects.toThrow(`"${protectedPath}" must exist`);
  });

  it.runIf(process.platform === "linux")("binds resolved worktree paths rather than raw pointer paths", async () => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const gitDirPointer = `${gitDir}/../workspace`;
    const commonPointer = `${commonDir}/worktrees/..`;
    await fs.writeFile(path.join(workspace, ".git"), `gitdir: ${gitDirPointer}\n`);
    await fs.writeFile(path.join(gitDir, "commondir"), `${commonPointer}\n`);
    const { args } = await worktreeSandbox(workspace);
    expectWorktreeMounts(args, workspace, await fs.realpath(commonDir), await fs.realpath(gitDir));
    expect(args).not.toContain(gitDirPointer);
    expect(args).not.toContain(commonPointer);
    const start = args.lastIndexOf(commonDir) - 2;
    const end = args.lastIndexOf(path.join(workspace, ".git"));
    for (let index = start; index < end; index++) {
      if (args[index] !== "--bind" && args[index] !== "--ro-bind") continue;
      expect(args[index + 1]).toBe(await fs.realpath(args[index + 1]));
      expect(args[index + 2]).toBe(args[index + 1]);
    }
  });

  it.runIf(process.platform === "linux").each(["malformed .git", "missing commondir"])(
    "adds no mounts for unreadable gitdir metadata: %s",
    async (scenario) => {
      const { workspace, commonDir, gitDir } = await createGitWorktree();
      await fs.rm(path.join(workspace, ".git"));
      const baseline = await worktreeSandbox(workspace);
      await fs.writeFile(path.join(workspace, ".git"), scenario === "malformed .git" ? "invalid\n" : `gitdir: ${gitDir}\n`);
      if (scenario === "missing commondir") await fs.rm(path.join(gitDir, "commondir"));
      const target = await worktreeSandbox(workspace);
      expect(target.args).toEqual(baseline.args);
      expect(target.args).not.toContain(commonDir);
    },
  );

  it.runIf(process.platform === "linux").each(["hooks", "config", "objects", "refs"])(
    "rejects missing %s before mounting writable common metadata",
    async (entry) => {
      const { workspace, commonDir } = await createGitWorktree();
      await fs.rm(path.join(commonDir, entry), { recursive: true });
      await expect(worktreeSandbox(workspace)).rejects.toThrow(`"${path.join(commonDir, entry)}" must exist`);
      await expect(fs.lstat(path.join(commonDir, entry))).rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it.runIf(process.platform === "linux").each([
    "empty gitdir", "multiline gitdir", "missing gitdir", "empty commondir", "multiline commondir", "wrong layout",
    "gitdir trailing space", "common trailing space",
    "gitdir symlink traversal", "commondir symlink traversal",
    ".git symlink", "commondir symlink", "gitdir symlink", "worktrees symlink", "common symlink",
  ])("adds no mounts for invalid worktree metadata: %s", async (scenario) => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const gitFile = path.join(workspace, ".git");
    const commonFile = path.join(gitDir, "commondir");
    await fs.rm(gitFile);
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(gitFile, `gitdir: ${gitDir}\n`);
    if (scenario === "empty gitdir") await fs.writeFile(gitFile, "gitdir: \n");
    if (scenario === "multiline gitdir") await fs.writeFile(gitFile, `gitdir: ${gitDir}\nextra\n`);
    if (scenario === "missing gitdir") await fs.rm(gitDir, { recursive: true });
    if (scenario === "empty commondir") await fs.writeFile(commonFile, "\n");
    if (scenario === "multiline commondir") await fs.writeFile(commonFile, "../..\nextra\n");
    if (scenario === "wrong layout") await fs.writeFile(commonFile, "../../..\n");
    if (scenario === "gitdir trailing space") {
      await fs.rename(gitDir, `${gitDir} `);
      await fs.writeFile(gitFile, `gitdir: ${gitDir} \n`);
    }
    if (scenario === "common trailing space") {
      await fs.rename(commonDir, `${commonDir} `);
      await fs.writeFile(gitFile, `gitdir: ${path.join(`${commonDir} `, "worktrees", "workspace")}\n`);
    }
    if (scenario === "gitdir symlink traversal" || scenario === "commondir symlink traversal") {
      await fs.mkdir(path.join(workspace, "deep"));
      if (scenario === "gitdir symlink traversal") {
        const link = path.join(path.dirname(workspace), "link");
        await fs.symlink(path.join(workspace, "deep"), link);
        await fs.writeFile(gitFile, `gitdir: ${link}/../repository/.git/worktrees/workspace\n`);
      } else {
        await fs.symlink(path.join(workspace, "deep"), path.join(commonDir, "link"));
        await fs.writeFile(commonFile, `${commonDir}/link/..\n`);
      }
    }
    const symlinkPaths: Record<string, string> = {
      ".git symlink": gitFile,
      "commondir symlink": commonFile,
      "gitdir symlink": gitDir,
      "worktrees symlink": path.dirname(gitDir),
      "common symlink": commonDir,
    };
    const symlinkPath = symlinkPaths[scenario];
    if (symlinkPath) {
      await fs.rename(symlinkPath, `${symlinkPath}-real`);
      await fs.symlink(`${symlinkPath}-real`, symlinkPath);
    }
    expect((await worktreeSandbox(workspace)).args).toEqual(baseline.args);
  });

  it.runIf(process.platform === "linux")("adds no worktree mounts for a bare repository without logs", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-bare-git-worktree-"));
    cleanup.push(root);
    const repository = path.join(root, "repository");
    const bare = path.join(root, "b.git");
    const workspace = path.join(root, "workspace");
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
    await execFileAsync("git", ["init", "--initial-branch=main", repository], { env });
    await execFileAsync("git", ["-C", repository, "-c", "user.name=Test", "-c", "user.email=test@example.com",
      "commit", "--allow-empty", "-m", "Initial"], { env });
    await execFileAsync("git", ["init", "--bare", "--initial-branch=main", bare], { env });
    await execFileAsync("git", ["-C", repository, "push", bare, "main"], { env });
    await execFileAsync("git", ["-C", bare, "worktree", "add", workspace, "main"], { env });

    const logsPath = path.join(bare, "logs");
    await expect(fs.lstat(logsPath)).rejects.toMatchObject({ code: "ENOENT" });
    const gitFile = path.join(workspace, ".git");
    const gitFileContents = await fs.readFile(gitFile, "utf8");
    await fs.rm(gitFile);
    const baseline = await worktreeSandbox(workspace);
    await fs.writeFile(gitFile, gitFileContents);

    const target = await worktreeSandbox(workspace);
    expect(target.args).toEqual(baseline.args);
    expect(target.args).not.toContain(bare);
    await expect(fs.lstat(logsPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.runIf(process.platform === "linux").each(["hooks", "config", "objects", "refs", "logs"])(
    "rejects symlinked %s before mounting writable common metadata",
    async (entry) => {
      const { workspace, commonDir } = await createGitWorktree();
      const protectedPath = path.join(commonDir, entry);
      await fs.rename(protectedPath, `${protectedPath}-real`);
      await fs.symlink(`${protectedPath}-real`, protectedPath);
      await expect(worktreeSandbox(workspace)).rejects.toThrow(`"${protectedPath}" must exist`);
    },
  );

  it.runIf(process.platform === "linux")("rejects logs when it is not a directory", async () => {
    const { workspace, commonDir } = await createGitWorktree();
    const logsPath = path.join(commonDir, "logs");
    await fs.rm(logsPath, { recursive: true });
    await fs.writeFile(logsPath, "not a directory");
    await expect(worktreeSandbox(workspace)).rejects.toThrow(
      `"${logsPath}" must exist with its expected type and no symlinks.`,
    );
  });

  it.runIf(process.platform === "linux")("reapplies ordered worktree mounts after overlapping managed paths", async () => {
    const { workspace, commonDir, gitDir } = await createGitWorktree();
    const target = await buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: [],
      cwd: workspace,
      options: {
        workspaceDir: workspace,
        filesystemScope: "workspace",
        managedPaths: [
          { path: commonDir, access: "ro" },
          { path: gitDir, access: "rw" },
          { path: path.join(commonDir, "config"), access: "rw" },
        ],
      },
    });
    expectWorktreeMounts(target.args, workspace, commonDir, gitDir);
  });

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP))(
    "rejects protected Git metadata writes with EROFS while allowing own metadata writes and commits",
    async () => {
      const { repository, workspace, commonDir, gitDir } = await createGitWorktree();
      const peer = path.join(commonDir, "worktrees", "peer");
      await fs.mkdir(peer);
      const moduleConfig = path.join(commonDir, "modules", "x", "config");
      await fs.mkdir(path.dirname(moduleConfig), { recursive: true });
      const commonWorktreeConfig = path.join(commonDir, "config.worktree");
      const ownWorktreeConfig = path.join(gitDir, "config.worktree");
      const attributes = path.join(commonDir, "info", "attributes");
      for (const file of [moduleConfig, commonWorktreeConfig, ownWorktreeConfig, attributes]) {
        await fs.writeFile(file, "# existing metadata\n");
      }
      // Keep hooks enabled and prove a real hook runs through the read-only hooks mount.
      await fs.writeFile(path.join(commonDir, "hooks", "pre-commit"), "#!/bin/sh\nprintf hook-ran > hook-ran.txt\n", { mode: 0o755 });
      const target = await worktreeSandbox(workspace);
      expectWorktreeMounts(target.args, workspace, commonDir, gitDir, [
        path.join(commonDir, "modules"), commonWorktreeConfig, ownWorktreeConfig, path.join(commonDir, "info"),
      ]);
      // Config must exist for strict parsing and its explicit ro-bind. Removing
      // it before launch would reject setup, so exercise overwrite here; absent
      // config is covered by the fail-closed setup test above.
      const protectedFiles = [
        path.join(commonDir, "hooks", "x"), path.join(commonDir, "config"), path.join(peer, "x"),
        path.join(commonDir, "commondir"), path.join(commonDir, "evil"), path.join(commonDir, "packed-refs"),
        moduleConfig, commonWorktreeConfig, ownWorktreeConfig, attributes,
        path.join(gitDir, "commondir"), path.join(gitDir, "gitdir"), path.join(workspace, ".git"),
      ];
      const ownFiles = ["HEAD", "index"].map((file) => path.join(gitDir, file));
      const script = [
        "const fs = require('node:fs');",
        "const { execFileSync } = require('node:child_process');",
        `for (const file of ${JSON.stringify(protectedFiles)}) {`,
        "  try { fs.writeFileSync(file, 'forbidden'); process.exit(9); } catch (error) {",
        "    if (error.code !== 'EROFS') throw error;",
        "  }",
        "}",
        `for (const file of ${JSON.stringify(ownFiles)}) fs.writeFileSync(file, fs.readFileSync(file));`,
        // The per-worktree reflog starts empty in its private tmpfs.
        `fs.writeFileSync(${JSON.stringify(path.join(gitDir, "logs", "HEAD"))}, '');`,
        `fs.writeFileSync(${JSON.stringify(path.join(gitDir, "own-ok"))}, 'ok');`,
        "fs.writeFileSync('committed.txt', 'sandbox commit\\n');",
        "const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };",
        "execFileSync('git', ['add', 'committed.txt'], { env });",
        "execFileSync('git', ['-c', 'user.name=Test', '-c', 'user.email=test@example.com',",
        "  'commit', '--no-gpg-sign', '-m', 'Sandbox commit'], { env });",
        "if (execFileSync('git', ['branch', '--show-current'], { env, encoding: 'utf8' }).trim() !== 'own') process.exit(10);",
        "fs.writeFileSync('sandbox-commit-sha', execFileSync('git', ['rev-parse', 'HEAD'], { env }));",
      ].join("\n");
      const result = await runChildProcess("git-worktree-sandbox-test", process.execPath, ["-e", script], {
        cwd: workspace,
        env: {},
        timeoutSec: 10,
        graceSec: 1,
        onLog: async () => {},
        localProcessSandbox: {
          workspaceDir: workspace,
          filesystemScope: "workspace",
          command: process.env.PAPERCLIP_TEST_BWRAP,
        },
      });
      expect(result.exitCode, result.stderr).toBe(0);
      await expect(fs.readFile(path.join(gitDir, "own-ok"), "utf8")).resolves.toBe("ok");
      await expect(fs.readFile(path.join(workspace, "hook-ran.txt"), "utf8")).resolves.toBe("hook-ran");
      for (const entry of ["commondir", "evil", "packed-refs"]) {
        await expect(fs.lstat(path.join(commonDir, entry))).rejects.toMatchObject({ code: "ENOENT" });
      }
      const sandboxSha = (await fs.readFile(path.join(workspace, "sandbox-commit-sha"), "utf8")).trim();
      expect(sandboxSha).toMatch(/^[0-9a-f]{40}$/);
      // Resolve the shared branch from the HOST main checkout after sandbox exit.
      const commit = await execFileAsync("git", ["-C", repository, "log", "-1", "--format=%H%n%s", "own"], {
        env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
      });
      expect(commit.stdout.trim()).toBe(`${sandboxSha}\nSandbox commit`);
    },
  );

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP))(
    "discards sandbox reflog writes and symlink planting without changing host logs",
    async () => {
      const { repository, workspace, commonDir, gitDir } = await createGitWorktree();
      const logs = [path.join(commonDir, "logs"), path.join(gitDir, "logs")];
      const planted = [path.join(logs[0], "refs", "heads", "own"), path.join(logs[1], "HEAD")];
      const before = await Promise.all(logs.map(hashTree));
      const hostFile = path.join(path.dirname(workspace), "host-shell-rc");
      await fs.writeFile(hostFile, "host bytes must survive\n");
      const script = [
        "const fs = require('node:fs');",
        "const { execFileSync } = require('node:child_process');",
        "fs.writeFileSync('committed.txt', 'sandbox commit\\n');",
        "const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };",
        "execFileSync('git', ['add', 'committed.txt'], { env });",
        "execFileSync('git', ['-c', 'user.name=Test', '-c', 'user.email=test@example.com',",
        "  'commit', '--no-gpg-sign', '-m', 'Isolated reflogs'], { env });",
        `for (const file of ${JSON.stringify(planted)}) {`,
        // Require real writes in BOTH tmpfs roots before replacing the files.
        "  if (!fs.readFileSync(file, 'utf8').includes('Isolated reflogs')) process.exit(11);",
        `  execFileSync('ln', ['-sf', ${JSON.stringify(hostFile)}, file]);`,
        `  if (fs.readlinkSync(file) !== ${JSON.stringify(hostFile)}) process.exit(12);`,
        "}",
      ].join("\n");
      const result = await runChildProcess("git-reflog-isolation-test", process.execPath, ["-e", script], {
        cwd: workspace,
        env: {},
        timeoutSec: 10,
        graceSec: 1,
        onLog: async () => {},
        localProcessSandbox: {
          workspaceDir: workspace,
          filesystemScope: "workspace",
          command: process.env.PAPERCLIP_TEST_BWRAP,
        },
      });
      expect(result.exitCode, result.stderr).toBe(0);
      expect(await Promise.all(logs.map(hashTree))).toEqual(before);
      for (const file of planted) expect((await fs.lstat(file)).isSymbolicLink()).toBe(false);
      expect(await fs.readFile(hostFile, "utf8")).toBe("host bytes must survive\n");
      const commit = await execFileAsync("git", ["-C", repository, "log", "-1", "--format=%s", "own"]);
      expect(commit.stdout.trim()).toBe("Isolated reflogs");
    },
  );

  it.runIf(process.platform === "linux")("binds a confined absolute alias to the synchronized workspace", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-fs-alias-"));
    cleanup.push(root);
    const workspace = path.join(root, "workspace");
    await fs.mkdir(workspace);

    const target = await buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: workspace,
      options: {
        workspaceDir: workspace,
        filesystemScope: "workspace",
        pathAliases: [{ path: "/app", target: workspace }],
      },
    });

    expect(target.args).toEqual(expect.arrayContaining(["--bind", workspace, "/app"]));
  });

  it.runIf(process.platform === "linux")("rejects writable out-of-tree paths without an outbound restore mapping", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-fs-outbound-"));
    cleanup.push(root);
    const workspace = path.join(root, "workspace");
    const outside = path.join(root, "outside");
    await fs.mkdir(workspace);
    await fs.mkdir(outside);

    await expect(buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: workspace,
      options: {
        workspaceDir: workspace,
        filesystemScope: "workspace",
        extraPaths: [{ path: outside, access: "rw" }],
      },
    })).rejects.toThrow("has no outbound restore mapping");
  });

  it.runIf(process.platform === "linux")("builds a network-only namespace without changing filesystem visibility", async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-network-sandbox-"));
    cleanup.push(workspace);
    const target = await buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: ["-e", "console.log('ok')"],
      cwd: workspace,
      options: { workspaceDir: workspace, networkScope: "deny" },
    });

    expect(target.args).toContain("--unshare-net");
    expect(target.args).toContain("--bind");
    expect(target.args).not.toContain("--tmpfs");
    expect(target.env?.HTTP_PROXY).toBeUndefined();
  });

  it.runIf(process.platform === "linux")("forwards allowed proxy targets with a deep TMPDIR and rejects other hosts", async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-network-proxy-"));
    cleanup.push(workspace);
    const deepTmpDir = path.join(workspace, ...Array.from({ length: 6 }, () => "deep-temporary-directory-segment"));
    await fs.mkdir(deepTmpDir, { recursive: true });
    const server = http.createServer((_request, response) => response.end("allowed-response"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected TCP test server address.");
    const target = await withTmpDir(deepTmpDir, () =>
      buildLocalProcessSandboxSpawnTarget({
        executable: process.execPath,
        args: ["-e", "process.exit(0)"],
        cwd: workspace,
        options: {
          workspaceDir: workspace,
          filesystemScope: "workspace",
          networkScope: "allowlist",
          networkAllowlist: [`127.0.0.1:${address.port}`],
        },
      }),
    );
    const delimiterIndex = target.args.indexOf("--");
    const socketPath = target.args[delimiterIndex + 3];
    expect(Buffer.byteLength(path.join(deepTmpDir, "paperclip-network-sandbox-XXXXXX", "proxy.sock"))).toBeGreaterThan(107);
    expect(Buffer.byteLength(socketPath)).toBeLessThanOrEqual(107);
    expect(socketPath).toMatch(/^\/tmp\/paperclip-network-sandbox-/);
    expect(target.args).toContain(path.dirname(socketPath));
    const request = (url: string) => new Promise<{ status: number; contentType: string | null; body: string }>((resolve, reject) => {
      const outgoing = http.request({ socketPath, path: url, headers: { host: new URL(url).host } }, (response) => {
        let body = "";
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => resolve({
          status: response.statusCode ?? 0,
          contentType: typeof response.headers["content-type"] === "string" ? response.headers["content-type"] : null,
          body,
        }));
      });
      outgoing.on("error", reject);
      outgoing.end();
    });

    try {
      await expect(request(`http://127.0.0.1:${address.port}/canary`)).resolves.toEqual({
        status: 200,
        contentType: null,
        body: "allowed-response",
      });
      await expect(request("http://example.com/")).resolves.toEqual({
        status: 403,
        contentType: "application/json; charset=utf-8",
        body: '{"error":{"code":"network_target_denied","message":"Network target denied by Paperclip sandbox policy."}}\n',
      });
      const connectResponse = await new Promise<string>((resolve, reject) => {
        const socket = net.createConnection(socketPath, () => {
          socket.end("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        });
        let response = "";
        socket.setEncoding("utf8");
        socket.on("data", (chunk) => { response += chunk; });
        socket.on("end", () => resolve(response));
        socket.on("error", reject);
      });
      expect(connectResponse).toContain("HTTP/1.1 403 Forbidden\r\n");
      expect(connectResponse).toContain("Content-Type: application/json; charset=utf-8\r\n");
      expect(connectResponse).toContain(
        '{"error":{"code":"network_target_denied","message":"Network target denied by Paperclip sandbox policy."}}\n',
      );
    } finally {
      await target.cleanup?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it.runIf(process.platform === "linux")("always permits trusted Paperclip control-plane URLs", async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-network-trusted-"));
    cleanup.push(workspace);
    const server = http.createServer((_request, response) => response.end("control-plane-response"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Expected TCP test server address.");
    const target = await buildLocalProcessSandboxSpawnTarget({
      executable: process.execPath,
      args: ["-e", "process.exit(0)"],
      cwd: workspace,
      options: {
        workspaceDir: workspace,
        networkScope: "allowlist",
        networkAllowlist: ["api.openai.com"],
        networkTrustedUrls: [`http://127.0.0.1:${address.port}/api/issues/issue-1`],
      },
    });
    const delimiterIndex = target.args.indexOf("--");
    const socketPath = target.args[delimiterIndex + 3];

    try {
      const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const outgoing = http.request({
          socketPath,
          path: `http://127.0.0.1:${address.port}/api/issues/issue-1`,
          headers: { host: `127.0.0.1:${address.port}` },
        }, (incoming) => {
          let body = "";
          incoming.on("data", (chunk) => { body += chunk; });
          incoming.on("end", () => resolve({ status: incoming.statusCode ?? 0, body }));
        });
        outgoing.on("error", reject);
        outgoing.end();
      });
      expect(response).toEqual({ status: 200, body: "control-plane-response" });
    } finally {
      await target.cleanup?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("fails clearly when Bubblewrap is unavailable", async () => {
    const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-fs-sandbox-missing-"));
    cleanup.push(workspace);
    await expect(
      runChildProcess("filesystem-sandbox-missing", process.execPath, ["-e", "process.exit(0)"], {
        cwd: workspace,
        env: {},
        timeoutSec: 10,
        graceSec: 1,
        onLog: async () => {},
        localProcessSandbox: {
          workspaceDir: workspace,
          filesystemScope: "workspace",
          command: path.join(workspace, "missing-bwrap"),
        },
      }),
    ).rejects.toThrow("requires Bubblewrap");
  });

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP))(
    "prevents reads outside the workspace while allowing workspace writes",
    async () => {
      const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-fs-sandbox-integration-"));
      cleanup.push(root);
      const workspace = path.join(root, "workspace");
      const outside = path.join(root, "canary.txt");
      const allowed = path.join(root, "allowed.txt");
      await fs.mkdir(workspace);
      await fs.writeFile(outside, "host-secret", "utf8");
      await fs.writeFile(allowed, "allowed-value", "utf8");

      const script = [
        "const fs = require('node:fs');",
        `try { fs.readFileSync(${JSON.stringify(outside)}, 'utf8'); process.exit(9); } catch (error) {`,
        "  if (!['ENOENT', 'EACCES'].includes(error.code)) throw error;",
        "}",
        `if (fs.readFileSync(${JSON.stringify(allowed)}, 'utf8') !== 'allowed-value') process.exit(8);`,
        "fs.writeFileSync('workspace-ok.txt', 'ok');",
      ].join("\n");
      const result = await runChildProcess("filesystem-sandbox-test", process.execPath, ["-e", script], {
        cwd: workspace,
        env: {},
        timeoutSec: 10,
        graceSec: 1,
        onLog: async () => {},
        localProcessSandbox: {
          workspaceDir: workspace,
          filesystemScope: "workspace",
          extraPaths: [{ path: allowed, access: "ro" }],
          command: process.env.PAPERCLIP_TEST_BWRAP,
        },
      });

      expect(result.exitCode, result.stderr).toBe(0);
      await expect(fs.readFile(path.join(workspace, "workspace-ok.txt"), "utf8")).resolves.toBe("ok");
    },
  );

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP && process.env.PAPERCLIP_TEST_SANDBOX_BUILD))(
    "runs the adapter-utils TypeScript build inside the confined workspace",
    async () => {
      const workspace = process.cwd();
      const result = await runChildProcess(
        "filesystem-sandbox-build-test",
        path.join(workspace, "node_modules", ".bin", "tsc"),
        ["--noEmit", "-p", "packages/adapter-utils/tsconfig.json"],
        {
          cwd: workspace,
          env: {},
          timeoutSec: 60,
          graceSec: 2,
          onLog: async () => {},
          localProcessSandbox: {
            workspaceDir: workspace,
            filesystemScope: "workspace",
            command: process.env.PAPERCLIP_TEST_BWRAP,
          },
        },
      );

      expect(result.exitCode, result.stderr).toBe(0);
    },
  );

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP))(
    "denies direct network egress",
    async () => {
      const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-network-deny-"));
      cleanup.push(workspace);
      const server = http.createServer((_request, response) => response.end("host-network"));
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Expected TCP test server address.");
      const script = `require("node:http").get("http://127.0.0.1:${address.port}", () => process.exit(9)).on("error", () => process.exit(0));`;
      try {
        const result = await runChildProcess("network-sandbox-deny-test", process.execPath, ["-e", script], {
          cwd: workspace,
          env: {},
          timeoutSec: 10,
          graceSec: 1,
          onLog: async () => {},
          localProcessSandbox: {
            workspaceDir: workspace,
            networkScope: "deny",
            command: process.env.PAPERCLIP_TEST_BWRAP,
          },
        });
        expect(result.exitCode, result.stderr).toBe(0);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP))(
    "allows only configured network targets through the proxy bridge",
    async () => {
      const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-network-allowlist-"));
      cleanup.push(workspace);
      const server = http.createServer((_request, response) => response.end("allowed-response"));
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Expected TCP test server address.");
      const targetUrl = `http://127.0.0.1:${address.port}/canary`;
      const deniedUrl = "http://example.com/";
      const script = `
const http = require("node:http");
const proxy = new URL(process.env.HTTP_PROXY);
function request(url) {
  return new Promise((resolve, reject) => {
    http.get({ hostname: proxy.hostname, port: proxy.port, path: url }, (response) => {
      let body = "";
      response.on("data", (chunk) => body += chunk);
      response.on("end", () => resolve({ status: response.statusCode, body }));
    }).on("error", reject);
  });
}
(async () => {
  const allowed = await request(${JSON.stringify(targetUrl)});
  const denied = await request(${JSON.stringify(deniedUrl)});
  if (allowed.status !== 200 || allowed.body !== "allowed-response" || denied.status !== 403) process.exit(8);
})().catch((error) => { console.error(error); process.exit(7); });
`;
      try {
        const deepTmpDir = path.join(workspace, ...Array.from({ length: 6 }, () => "deep-temporary-directory-segment"));
        await fs.mkdir(deepTmpDir, { recursive: true });
        const result = await withTmpDir(deepTmpDir, () =>
          runChildProcess(
            "network-sandbox-allowlist-test",
            process.execPath,
            ["-e", script],
            {
              cwd: workspace,
              env: {},
              timeoutSec: 10,
              graceSec: 1,
              onLog: async () => {},
              localProcessSandbox: {
                workspaceDir: workspace,
                filesystemScope: "workspace",
                networkScope: "allowlist",
                networkAllowlist: [`127.0.0.1:${address.port}`],
                command: process.env.PAPERCLIP_TEST_BWRAP,
              },
            },
          ),
        );
        expect(result.exitCode, result.stderr).toBe(0);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    },
  );
});

/**
 * Fork review of ce523a92b: the repo-controlled and profile-controlled execution vectors
 * (`.git/commondir`, `.git` replaced by a gitfile or symlink, symlinked directories in profile
 * paths, hard links) are one class. Decisions, closing the class instead of the vectors:
 *
 * (A) An SSH target running with a confinement scope (`spec.confinedRun === true`) never sources
 *     user dotfiles (`~/.profile`, `~/.bash_profile`, `~/.bashrc`, `~/.zprofile`) in any SSH
 *     command; it may source only `/etc/profile` and `/etc/profile.d/*`. Unconfined targets keep
 *     today's behaviour (ssh.ts:1313-1318, and the same in `buildSshSpawnTarget`).
 * (B) For such targets every host-side git command on the remote workspace runs inside its own
 *     bwrap: `--ro-bind / /`, `--unshare-net`, a rw bind of the workspace only, no proxy, plus
 *     `-c core.hooksPath=/dev/null -c core.fsmonitor=false`. Contract: the shell prefix comes from
 *     `remoteGitCommand(remoteDir, { confined, sandboxCommand? })` in `git-workspace-sync.ts`
 *     (unconfined → `${REMOTE_GIT_COMMAND} -C <dir>`), and no script builds `git … -C` any other
 *     way.
 *
 * The behavioural test runs real Bubblewrap and is gated on `PAPERCLIP_TEST_BWRAP` like the
 * existing sandbox tests.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const captured = vi.hoisted(() => ({ ssh: [] as string[][] }));

vi.mock("node:child_process", async () => {
  const actual = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const execFile = ((file: string, args: string[], options: unknown, callback: unknown) => {
    if (file === "ssh") {
      captured.ssh.push(args);
      const done = (typeof options === "function" ? options : callback) as
        (error: Error | null, stdout: string, stderr: string) => void;
      done(null, "", "");
      return { pid: 1 } as never;
    }
    return (actual.execFile as unknown as (...rest: unknown[]) => unknown)(file, args, options, callback);
  }) as unknown as typeof actual.execFile;
  return { ...actual, execFile };
});

import * as gitSync from "./git-workspace-sync.js";
import { REMOTE_GIT_COMMAND } from "./git-workspace-sync.js";
import { buildSshSpawnTarget, runSshCommand } from "./ssh.js";

const SPEC = {
  host: "127.0.0.1",
  port: 2222,
  username: "factory",
  remoteWorkspacePath: "/home/factory/workspaces",
  remoteCwd: "/home/factory/workspaces/run-1",
  privateKey: null,
  knownHosts: null,
  strictHostKeyChecking: false,
};
const USER_DOTFILES = [".profile", ".bash_profile", ".bashrc", ".zprofile"];

afterEach(() => {
  captured.ssh.length = 0;
});

function remoteScript(sshArgs: string[]): string {
  return sshArgs[sshArgs.length - 1] ?? "";
}

describe("(A) confined SSH runs do not source user dotfiles", () => {
  it("runSshCommand: confined sources only /etc/profile", async () => {
    await runSshCommand({ ...SPEC, confinedRun: true } as never, "true");
    const script = remoteScript(captured.ssh[0] ?? []);
    expect(script).toContain("/etc/profile");
    for (const dotfile of USER_DOTFILES) expect(script).not.toContain(dotfile);
  });

  it("runSshCommand: unconfined keeps today's profile chain", async () => {
    await runSshCommand(SPEC as never, "true");
    const script = remoteScript(captured.ssh[0] ?? []);
    for (const dotfile of USER_DOTFILES) expect(script).toContain(dotfile);
  });

  it("buildSshSpawnTarget: confined sources only /etc/profile", async () => {
    const target = await buildSshSpawnTarget({
      spec: { ...SPEC, confinedRun: true } as never,
      command: "codex",
      args: ["exec", "-"],
      env: {},
    });
    try {
      const script = target.args.join(" ");
      expect(script).toContain("/etc/profile");
      for (const dotfile of USER_DOTFILES) expect(script).not.toContain(dotfile);
    } finally {
      await target.cleanup();
    }
  });

  it("buildSshSpawnTarget: unconfined keeps today's profile chain", async () => {
    const target = await buildSshSpawnTarget({ spec: SPEC as never, command: "codex", args: [], env: {} });
    try {
      for (const dotfile of USER_DOTFILES) expect(target.args.join(" ")).toContain(dotfile);
    } finally {
      await target.cleanup();
    }
  });
});

type RemoteGit = (remoteDir: string, options: { confined: boolean; sandboxCommand?: string }) => string;
const remoteGitCommand = (gitSync as Record<string, unknown>).remoteGitCommand as RemoteGit | undefined;

function tokens(command: string): string[] {
  // Enough for the helper's output: words and single-quoted words.
  return [...command.matchAll(/'((?:[^']|'\\'')*)'|(\S+)/g)].map((m) => m[1] !== undefined
    ? m[1].replace(/'\\''/g, "'")
    : m[2]);
}

describe("(B) host-side git on a confined workspace runs inside bwrap", () => {
  it("confined: read-only root, no network, only the workspace writable, hardened git", () => {
    expect(typeof remoteGitCommand).toBe("function");
    const argv = tokens(remoteGitCommand!("/home/factory/workspaces/run-1", { confined: true }));
    expect(path.posix.basename(argv[0] ?? "")).toBe("bwrap");
    const separator = argv.indexOf("--");
    expect(separator).toBeGreaterThan(0);
    const options = argv.slice(0, separator);
    const pairs = (flag: string) => options.flatMap((value, i) => value === flag ? [[options[i + 1], options[i + 2]]] : []);
    expect(pairs("--ro-bind")).toContainEqual(["/", "/"]);
    expect(options).toContain("--unshare-net");
    expect([...pairs("--bind"), ...pairs("--bind-try"), ...pairs("--dev-bind")])
      .toEqual([["/home/factory/workspaces/run-1", "/home/factory/workspaces/run-1"]]);
    expect(argv.slice(separator + 1, separator + 7)).toEqual([
      "git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C",
    ]);
    expect(argv[separator + 7]).toBe("/home/factory/workspaces/run-1");
    expect(argv.join(" ")).not.toContain("proxy");
  });

  it("unconfined: today's hardened git without bwrap", () => {
    expect(typeof remoteGitCommand).toBe("function");
    expect(remoteGitCommand!("/w", { confined: false })).toBe(`${REMOTE_GIT_COMMAND} -C '/w'`);
  });

  it("no script builds `git … -C` except through remoteGitCommand", async () => {
    for (const file of ["./ssh.ts", "./git-workspace-sync.ts"]) {
      const source = await fs.readFile(new URL(file, import.meta.url), "utf8");
      const offenders = source.split("\n").filter((line) =>
        /\$\{REMOTE_GIT_COMMAND\}\s+-C\b|`git\s+(?:-c\s+\S+\s+)*-C\s/.test(line)
        && !line.includes("function remoteGitCommand"));
      expect({ file, offenders }).toEqual({ file, offenders: [] });
    }
  });

  it.runIf(Boolean(process.env.PAPERCLIP_TEST_BWRAP))(
    "a repo filter cannot write outside the workspace during host-side checkout",
    async () => {
      expect(typeof remoteGitCommand).toBe("function");
      const root = await fs.mkdtemp(path.join(os.tmpdir(), "pcp-git-filter-"));
      try {
        const workspace = path.join(root, "workspace");
        const marker = path.join(root, "outside-marker");
        await fs.mkdir(workspace, { recursive: true });
        const git = (...args: string[]) => execFileSync("git", ["-C", workspace, ...args], { stdio: "ignore" });
        git("init", "-q");
        git("config", "user.email", "t@example.test");
        git("config", "user.name", "t");
        await fs.writeFile(path.join(workspace, "file.txt"), "content\n");
        await fs.writeFile(path.join(workspace, ".gitattributes"), "*.txt filter=x\n");
        git("add", ".");
        git("commit", "-qm", "init");
        git("config", "filter.x.smudge", `sh -c 'touch ${marker}; cat'`);
        git("config", "filter.x.required", "false");
        await fs.rm(path.join(workspace, "file.txt"));
        const prefix = remoteGitCommand!(workspace, {
          confined: true,
          sandboxCommand: process.env.PAPERCLIP_TEST_BWRAP,
        });
        try {
          execFileSync("sh", ["-c", `${prefix} checkout --force -- file.txt`], { stdio: "ignore" });
        } catch {
          // A failing filter under the read-only root is acceptable; only the marker matters.
        }
        await expect(fs.stat(marker)).rejects.toThrow();
        // Control: the same checkout without the sandbox does run the filter.
        await fs.rm(path.join(workspace, "file.txt"), { force: true });
        execFileSync("sh", ["-c", `${REMOTE_GIT_COMMAND} -C '${workspace}' checkout --force -- file.txt`], { stdio: "ignore" });
        await expect(fs.stat(marker)).resolves.toBeTruthy();
      } finally {
        await fs.rm(root, { recursive: true, force: true });
      }
    },
    30_000,
  );
});

import type { BigIntStats } from "node:fs";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

export type LocalProcessSandboxAccess = "ro" | "rw";
export type LocalProcessNetworkScope = "deny" | "allowlist";

export interface LocalProcessSandboxPath {
  path: string;
  access: LocalProcessSandboxAccess;
}

export interface LocalProcessSandboxPathAlias {
  path: string;
  target: string;
}

export interface LocalProcessSandboxOptions {
  workspaceDir: string;
  filesystemScope?: "workspace" | null;
  managedPaths?: LocalProcessSandboxPath[];
  extraPaths?: LocalProcessSandboxPath[];
  pathAliases?: LocalProcessSandboxPathAlias[];
  outboundRestorePaths?: string[];
  homeDir?: string | null;
  networkScope?: LocalProcessNetworkScope | null;
  networkAllowlist?: string[];
  networkTrustedUrls?: string[];
  command?: string;
}

export interface LocalProcessSandboxSpawnTarget {
  command: string;
  args: string[];
  cwd: string;
  env?: Record<string, string | undefined>;
  cleanup?: () => Promise<void>;
}

interface NetworkAllowlistRule {
  hostname: string;
  port: string | null;
}

interface NetworkAllowlistProxy {
  close: () => Promise<void>;
}

const SYSTEM_READ_PATHS = [
  "/bin",
  "/sbin",
  "/usr",
  "/lib",
  "/lib64",
  "/etc/ca-certificates",
  "/etc/ssl",
  "/etc/resolv.conf",
  "/etc/hosts",
  "/etc/nsswitch.conf",
  "/etc/passwd",
  "/etc/group",
  "/etc/localtime",
  "/etc/timezone",
  "/etc/gitconfig",
] as const;

const PROXY_ENV_KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] as const;
const SANDBOX_PROXY_PORT = 31_337;
const UNIX_SOCKET_PATH_MAX_BYTES = 107;
const NETWORK_PROXY_TEMP_PREFIX = "paperclip-network-sandbox-";

function normalizeAbsolutePath(candidate: string, label: string): string {
  const trimmed = candidate.trim();
  if (!trimmed || !path.isAbsolute(trimmed)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  return path.resolve(trimmed);
}

async function pathExists(candidate: string): Promise<boolean> {
  return fs.lstat(candidate).then(() => true).catch(() => false);
}

function gitWorktreeConfigSafe(config: string): boolean {
  // Only accept the simple INI subset we can inspect without executing Git.
  // Includes, escapes/continuations and malformed syntax leave the setting uncertain.
  if (/[\0\\]|\r(?!\n)/.test(config)) return false;
  let section = "";
  for (const rawLine of config.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || /^[#;]/.test(line)) continue;
    if (line.startsWith("[")) {
      const header = /^\[([a-z0-9-]+)(?:[ \t]+("[^"\\]*"))?\][ \t]*(?:[#;].*)?$/i.exec(line);
      if (!header) return false;
      const name = header[1].toLowerCase();
      if (name === "include" || name === "includeif") return false;
      section = header[2] === undefined ? name : "subsection";
      continue;
    }
    const entry = /^([a-z][a-z0-9-]*)(?:[ \t]*=[ \t]*(.*))?$/i.exec(line);
    if (!section || !entry) return false;
    // Even an empty hooksPath can redirect hooks into a writable directory.
    // Reject every occurrence, rather than interpreting its value or precedence.
    if (section === "core" && entry[1].toLowerCase() === "hookspath") return false;
    let value = "";
    let quoted = false;
    for (const character of entry[2] ?? "") {
      if (character === '"') quoted = !quoted;
      if (!quoted && (character === "#" || character === ";")) break;
      value += character;
    }
    if (quoted) return false;
    if (section === "extensions" && entry[1].toLowerCase() === "worktreeconfig") {
      // A bare key is true. Deny any enabled or unknown value, even if repeated.
      const booleanValue = value.trim().replace(/^"([^"]*)"$/, "$1").toLowerCase();
      if (entry[2] === undefined || !["false", "no", "off", "0", ""].includes(booleanValue)) return false;
    }
  }
  return true;
}

async function gitWorktreePaths(workspaceDir: string): Promise<LocalProcessSandboxPath[]> {
  const checkedPaths: { candidate: string; resolved: string; directory: boolean; stat: BigIntStats }[] = [];
  const resolvePath = async (candidate: string, directory: boolean): Promise<string> => {
    const stat = await fs.lstat(candidate, { bigint: true }).catch(() => null);
    const resolved = await fs.realpath(candidate).catch(() => null);
    if (!stat || stat.isSymbolicLink() || !(directory ? stat.isDirectory() : stat.isFile())
      || resolved !== path.resolve(candidate)) {
      throw new Error(`Cannot sandbox Git worktree: "${candidate}" must exist with its expected type and no symlinks.`);
    }
    checkedPaths.push({ candidate, resolved, directory, stat });
    return resolved;
  };
  const gitFile = path.join(workspaceDir, ".git");
  let gitDir: string;
  let commonDir: string;
  let worktreesDir: string;
  let commonFile: string;
  let backPointer: string;
  try {
    const resolvedGitFile = await resolvePath(gitFile, false);
    const gitdir = /^gitdir: ([^\0\r\n]+)\r?\n?$/.exec(await fs.readFile(resolvedGitFile, "utf8"));
    if (!gitdir || !gitdir[1].trim()) return [];
    const gitDirPath = path.isAbsolute(gitdir[1]) ? gitdir[1] : `${workspaceDir}/${gitdir[1]}`;
    gitDir = await resolvePath(gitDirPath, true);
    commonFile = await resolvePath(path.join(gitDir, "commondir"), false);
    backPointer = await resolvePath(path.join(gitDir, "gitdir"), false);
    const commondir = /^([^\0\r\n]+)\r?\n?$/.exec(await fs.readFile(commonFile, "utf8"));
    if (!commondir || !commondir[1].trim()) return [];
    const commonDirPath = path.isAbsolute(commondir[1]) ? commondir[1] : `${gitDir}/${commondir[1]}`;
    commonDir = await resolvePath(commonDirPath, true);
    if (gitDir.trim() !== gitDir || commonDir.trim() !== commonDir) return [];
    worktreesDir = await resolvePath(path.join(commonDir, "worktrees"), true);
    if (path.dirname(gitDir) !== worktreesDir) return [];
  } catch {
    // Unreadable or unrecognized Git metadata must not grant additional access.
    return [];
  }
  const hooks = await resolvePath(path.join(commonDir, "hooks"), true);
  const config = await resolvePath(path.join(commonDir, "config"), false);
  try {
    if (!gitWorktreeConfigSafe(await fs.readFile(config, "utf8"))) return [];
  } catch {
    return [];
  }
  // The common root must stay read-only: newly created metadata (for example
  // commondir) can redirect host Git. Only allow writes needed for own commits.
  // A common dir without objects/ or refs/ is invalid; Git itself refuses it,
  // so treat it as corruption or tampering and fail loudly. logs/ is optional:
  // bare repos may disable core.logAllRefUpdates, so absent logs means no mounts.
  const writablePaths = await Promise.all(["objects", "refs"].map((entry) =>
    resolvePath(path.join(commonDir, entry), true)));
  const logsPath = path.join(commonDir, "logs");
  const logsExist = await fs.lstat(logsPath).then(() => true).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return false;
    throw error;
  });
  if (!logsExist) return [];
  writablePaths.push(await resolvePath(logsPath, true));
  const mounts: LocalProcessSandboxPath[] = [
    { path: commonDir, access: "ro" },
    ...writablePaths.map((resolved): LocalProcessSandboxPath => ({ path: resolved, access: "rw" })),
    { path: gitDir, access: "rw" },
    { path: hooks, access: "ro" },
    { path: config, access: "ro" },
    { path: commonFile, access: "ro" },
    { path: backPointer, access: "ro" },
  ];
  for (const [candidate, directory] of [
    [path.join(commonDir, "modules"), true],
    [path.join(commonDir, "config.worktree"), false],
    [path.join(gitDir, "config.worktree"), false],
    [path.join(commonDir, "info"), true],
  ] as const) {
    const exists = await fs.lstat(candidate).then(() => true).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return false;
      throw error;
    });
    if (exists) mounts.push({ path: await resolvePath(candidate, directory), access: "ro" });
  }
  mounts.push({ path: gitFile, access: "ro" });
  // Recheck identity, file size/mtime and pointer targets before args are built,
  // retaining the initially resolved paths for binds. The residual launch race
  // is accepted under a trusted launch window: bwrap binds by path and cannot
  // pin an inode or its contents. The sandboxed process does not exist yet when
  // these args are built; concurrent runs on the same repo remain an actor.
  try {
    for (const { candidate, resolved, directory, stat: initial } of checkedPaths) {
      const stat = await fs.lstat(candidate, { bigint: true });
      if (stat.isSymbolicLink() || !(directory ? stat.isDirectory() : stat.isFile())
        || stat.dev !== initial.dev || stat.ino !== initial.ino
        || (!directory && (stat.size !== initial.size || stat.mtimeNs !== initial.mtimeNs))
        || await fs.realpath(candidate) !== resolved) return [];
    }
    const gitdir = /^gitdir: ([^\0\r\n]+)\r?\n?$/.exec(await fs.readFile(gitFile, "utf8"));
    const commondir = /^([^\0\r\n]+)\r?\n?$/.exec(await fs.readFile(commonFile, "utf8"));
    if (!gitdir || !gitdir[1].trim() || !commondir || !commondir[1].trim()) return [];
    const gitDirPath = path.isAbsolute(gitdir[1]) ? gitdir[1] : `${workspaceDir}/${gitdir[1]}`;
    const commonDirPath = path.isAbsolute(commondir[1]) ? commondir[1] : `${gitDir}/${commondir[1]}`;
    if (path.resolve(gitDirPath) !== gitDir || await fs.realpath(gitDirPath) !== gitDir
      || path.resolve(commonDirPath) !== commonDir || await fs.realpath(commonDirPath) !== commonDir) return [];
  } catch {
    return [];
  }
  return mounts;
}

function parentDirectories(candidate: string): string[] {
  const directories: string[] = [];
  let current = path.dirname(candidate);
  while (current !== path.dirname(current)) {
    directories.push(current);
    current = path.dirname(current);
  }
  return directories.reverse();
}

function addParentDirectories(args: string[], created: Set<string>, candidate: string): void {
  for (const directory of parentDirectories(candidate)) {
    if (created.has(directory)) continue;
    args.push("--dir", directory);
    created.add(directory);
  }
}

async function nearestPackageRoot(candidate: string): Promise<string> {
  let current = path.dirname(candidate);
  while (current !== path.dirname(current)) {
    if (await pathExists(path.join(current, "package.json"))) return current;
    current = path.dirname(current);
  }
  return path.dirname(candidate);
}

async function executableReadPaths(command: string): Promise<string[]> {
  const paths = new Set<string>();
  paths.add(path.dirname(command));
  const realCommand = await fs.realpath(command).catch(() => command);
  paths.add(await nearestPackageRoot(realCommand));
  return Array.from(paths);
}

function parseNetworkAllowlistEntry(entry: string, index: number): NetworkAllowlistRule {
  const trimmed = entry.trim();
  if (!trimmed) throw new Error(`networkAllowlist[${index}] must not be empty.`);
  let hostname: string;
  let port: string | null;
  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      throw new Error("path");
    }
    hostname = parsed.hostname.toLowerCase();
    port = parsed.port || null;
  } catch {
    throw new Error(`networkAllowlist[${index}] must be a hostname, hostname:port, or origin URL.`);
  }
  if (!hostname || hostname === "*" || hostname.startsWith("*.")) {
    throw new Error(`networkAllowlist[${index}] must use an exact hostname; wildcards are not supported.`);
  }
  return { hostname, port };
}

export function parseLocalProcessNetworkAllowlist(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry, index) => {
    if (typeof entry !== "string") throw new Error(`networkAllowlist[${index}] must be a string.`);
    const rule = parseNetworkAllowlistEntry(entry, index);
    return rule.port ? `${rule.hostname}:${rule.port}` : rule.hostname;
  });
}

export function parseLocalProcessNetworkScope(value: unknown): LocalProcessNetworkScope | null {
  if (value == null || value === "") return null;
  if (value === "deny" || value === "allowlist") return value;
  throw new Error('networkScope must be "deny" or "allowlist".');
}

export function parseLocalProcessFilesystemScope(value: unknown): "workspace" | null {
  if (value == null || value === "") return null;
  if (value === "workspace") return value;
  throw new Error('filesystemScope must be "workspace".');
}

function isNetworkTargetAllowed(hostname: string, port: string, rules: NetworkAllowlistRule[]): boolean {
  const normalizedHostname = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return rules.some((rule) => rule.hostname === normalizedHostname && (rule.port === null || rule.port === port));
}

function assertUnixSocketPathLength(socketPath: string): void {
  const pathBytes = Buffer.byteLength(socketPath);
  if (pathBytes > UNIX_SOCKET_PATH_MAX_BYTES) {
    throw new Error(
      `Paperclip sandbox proxy socket path is ${pathBytes} bytes, exceeding the Linux limit of ${UNIX_SOCKET_PATH_MAX_BYTES}: ${socketPath}`,
    );
  }
}

async function createNetworkProxyTempDir(): Promise<string> {
  const candidates = Array.from(new Set(["/tmp", os.tmpdir()]));
  let lastError: unknown;
  for (const baseDir of candidates) {
    try {
      const tempDir = await fs.mkdtemp(path.join(baseDir, NETWORK_PROXY_TEMP_PREFIX));
      try {
        assertUnixSocketPathLength(path.join(tempDir, "proxy.sock"));
        return tempDir;
      } catch (error) {
        await fs.rm(tempDir, { recursive: true, force: true });
        lastError = error;
      }
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error("Unable to create a Linux-safe Paperclip sandbox proxy socket directory.", { cause: lastError });
}

function parseTrustedNetworkUrl(value: string): NetworkAllowlistRule | null {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return {
      hostname: parsed.hostname.toLowerCase(),
      port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    };
  } catch {
    return null;
  }
}

function writeProxyError(response: http.ServerResponse, status: number, code: string, message: string): void {
  const body = `${JSON.stringify({ error: { code, message } })}\n`;
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  }).end(body);
}

function connectProxyError(code: string, message: string): string {
  const body = `${JSON.stringify({ error: { code, message } })}\n`;
  return [
    "HTTP/1.1 403 Forbidden",
    "Connection: close",
    "Content-Type: application/json; charset=utf-8",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "",
    body,
  ].join("\r\n");
}

async function startNetworkAllowlistProxy(
  allowlist: string[],
  trustedUrls: string[],
  socketPath: string,
): Promise<NetworkAllowlistProxy> {
  assertUnixSocketPathLength(socketPath);
  const rules = [
    ...allowlist.map(parseNetworkAllowlistEntry),
    ...trustedUrls.map(parseTrustedNetworkUrl).filter((rule): rule is NetworkAllowlistRule => rule !== null),
  ];
  if (rules.length === 0) {
    throw new Error(
      'networkScope="allowlist" requires at least one valid networkAllowlist hostname or HTTP(S) networkTrustedUrl.',
    );
  }
  const server = http.createServer((request, response) => {
    let target: URL;
    try {
      target = new URL(request.url ?? "");
    } catch {
      writeProxyError(response, 400, "invalid_request_url", "Paperclip sandbox proxy requires an absolute request URL.");
      return;
    }
    const port = target.port || (target.protocol === "https:" ? "443" : "80");
    if (target.protocol !== "http:") {
      writeProxyError(response, 400, "https_requires_connect", "HTTPS targets must use CONNECT through the Paperclip sandbox proxy.");
      return;
    }
    if (!isNetworkTargetAllowed(target.hostname, port, rules)) {
      writeProxyError(response, 403, "network_target_denied", "Network target denied by Paperclip sandbox policy.");
      return;
    }
    const upstream = http.request(target, {
      method: request.method,
      headers: { ...request.headers, host: target.host },
    }, (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on("error", (error) => response.destroy(error));
    request.pipe(upstream);
  });
  server.on("connect", (request, clientSocket, head) => {
    const separator = request.url?.lastIndexOf(":") ?? -1;
    const hostname = separator > 0 ? request.url!.slice(0, separator).replace(/^\[|\]$/g, "") : "";
    const port = separator > 0 ? request.url!.slice(separator + 1) : "443";
    if (!hostname || !/^\d+$/.test(port) || !isNetworkTargetAllowed(hostname, port, rules)) {
      clientSocket.end(connectProxyError(
        "network_target_denied",
        "Network target denied by Paperclip sandbox policy.",
      ));
      return;
    }
    const upstream = net.connect(Number(port), hostname, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on("error", () => clientSocket.destroy());
    clientSocket.on("close", () => upstream.destroy());
  });
  const sockets = new Set<net.Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return {
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

async function createNetworkProxyBridge(): Promise<string> {
  const source = `
const net = require("node:net");
const { spawn } = require("node:child_process");
const socketPath = process.argv[2];
const executable = process.argv[3];
const args = process.argv.slice(4);
const server = net.createServer((client) => {
  const upstream = net.connect(socketPath);
  client.pipe(upstream);
  upstream.pipe(client);
  const close = () => { client.destroy(); upstream.destroy(); };
  client.on("error", close);
  upstream.on("error", close);
});
server.listen(${SANDBOX_PROXY_PORT}, "127.0.0.1", () => {
  const child = spawn(executable, args, { stdio: "inherit", env: process.env });
  const forward = (signal) => { if (!child.killed) child.kill(signal); };
  process.on("SIGTERM", () => forward("SIGTERM"));
  process.on("SIGINT", () => forward("SIGINT"));
  child.on("exit", (code, signal) => server.close(() => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code == null ? 1 : code);
  }));
});
`;
  return source.trimStart();
}

export async function buildLocalProcessSandboxSpawnTarget(input: {
  executable: string;
  args: string[];
  cwd: string;
  options: LocalProcessSandboxOptions;
}): Promise<LocalProcessSandboxSpawnTarget> {
  if (process.platform !== "linux") {
    throw new Error("Local process filesystem and network scopes are currently supported only on Linux.");
  }
  const filesystemScope = input.options.filesystemScope ?? null;
  const networkScope = input.options.networkScope ?? null;
  if (!filesystemScope && !networkScope) throw new Error("Local process sandbox requires a filesystem or network scope.");

  const workspaceDir = normalizeAbsolutePath(input.options.workspaceDir, "Sandbox workspaceDir");
  const cwd = normalizeAbsolutePath(input.cwd, "Sandbox cwd");
  if (filesystemScope === "workspace") {
    const relativeCwd = path.relative(workspaceDir, cwd);
    if (relativeCwd.startsWith("..") || path.isAbsolute(relativeCwd)) {
      throw new Error(`Sandbox cwd "${cwd}" must be inside workspaceDir "${workspaceDir}".`);
    }
    const outboundRestorePaths = (input.options.outboundRestorePaths ?? []).map((candidate, index) =>
      normalizeAbsolutePath(candidate, `Sandbox outboundRestorePaths[${index}]`));
    for (const [index, extraPath] of (input.options.extraPaths ?? []).entries()) {
      if (extraPath.access !== "rw") continue;
      const normalizedExtraPath = normalizeAbsolutePath(extraPath.path, `Sandbox extraPaths[${index}].path`);
      const relativeToWorkspace = path.relative(workspaceDir, normalizedExtraPath);
      const synchronized = !relativeToWorkspace.startsWith("..") && !path.isAbsolute(relativeToWorkspace);
      const restored = outboundRestorePaths.some((restorePath) => {
        const relative = path.relative(restorePath, normalizedExtraPath);
        return !relative.startsWith("..") && !path.isAbsolute(relative);
      });
      if (!synchronized && !restored) {
        throw new Error(
          `Writable sandbox path "${normalizedExtraPath}" is outside synchronized workspace "${workspaceDir}" and has no outbound restore mapping.`,
        );
      }
    }
  }

  const bwrapCommand = input.options.command?.trim() || "bwrap";
  const args = ["--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts"];
  const env: Record<string, string | undefined> = {};
  let cleanup: (() => Promise<void>) | undefined;
  let executable = input.executable;
  let executableArgs = input.args;

  if (filesystemScope === "workspace") {
    args.push("--tmpfs", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");
    const created = new Set<string>(["/", "/proc", "/dev", "/tmp"]);
    const mounted = new Set<string>();
    // On merged-usr hosts these paths are symlinks into /usr. Recreate the
    // links, but never bind over them: Bubblewrap cannot mount onto a symlink.
    // On hosts with separate directories, mount the directories below instead.
    for (const alias of ["/bin", "/sbin", "/lib", "/lib64"]) {
      const stat = await fs.lstat(alias).catch(() => null);
      if (!stat?.isSymbolicLink()) continue;
      const resolved = await fs.realpath(alias).catch(() => null);
      if (!resolved?.startsWith("/usr/")) continue;
      args.push("--symlink", await fs.readlink(alias), alias);
      created.add(alias);
      mounted.add(alias);
    }
    const addMount = (source: string, access: LocalProcessSandboxAccess) => {
      addParentDirectories(args, created, source);
      args.push(access === "rw" ? "--bind" : "--ro-bind", source, source);
      mounted.add(source);
      created.add(source);
    };
    const mount = async (source: string, access: LocalProcessSandboxAccess) => {
      const normalized = normalizeAbsolutePath(source, "Sandbox path");
      if (mounted.has(normalized) || !(await pathExists(normalized))) return;
      addMount(normalized, access);
    };
    for (const systemPath of SYSTEM_READ_PATHS) await mount(systemPath, "ro");
    for (const executablePath of await executableReadPaths(input.executable)) await mount(executablePath, "ro");
    if (networkScope === "allowlist") {
      for (const nodePath of await executableReadPaths(process.execPath)) await mount(nodePath, "ro");
    }
    for (const managedPath of input.options.managedPaths ?? []) await mount(managedPath.path, managedPath.access);
    for (const extraPath of input.options.extraPaths ?? []) await mount(extraPath.path, extraPath.access);
    await mount(workspaceDir, "rw");
    // Later binds override earlier ones: protect peers and executable Git metadata.
    for (const gitPath of await gitWorktreePaths(workspaceDir)) addMount(gitPath.path, gitPath.access);
    for (const [index, alias] of (input.options.pathAliases ?? []).entries()) {
      const aliasPath = normalizeAbsolutePath(alias.path, `Sandbox pathAliases[${index}].path`);
      const aliasTarget = normalizeAbsolutePath(alias.target, `Sandbox pathAliases[${index}].target`);
      const relativeTarget = path.relative(workspaceDir, aliasTarget);
      if (relativeTarget.startsWith("..") || path.isAbsolute(relativeTarget)) {
        throw new Error(
          `Sandbox path alias "${aliasPath}" must target the synchronized workspace "${workspaceDir}".`,
        );
      }
      if (!(await pathExists(aliasTarget))) {
        throw new Error(`Sandbox path alias target "${aliasTarget}" does not exist.`);
      }
      addParentDirectories(args, created, aliasPath);
      args.push("--bind", aliasTarget, aliasPath);
      created.add(aliasPath);
    }

    if (networkScope === "allowlist") {
      const tempDir = await createNetworkProxyTempDir();
      const socketPath = path.join(tempDir, "proxy.sock");
      const bridgePath = path.join(tempDir, "bridge.cjs");
      await fs.writeFile(bridgePath, await createNetworkProxyBridge(), { mode: 0o500 });
      const proxy = await startNetworkAllowlistProxy(
        input.options.networkAllowlist ?? [],
        input.options.networkTrustedUrls ?? [],
        socketPath,
      ).catch(async (error) => {
        await fs.rm(tempDir, { recursive: true, force: true });
        throw error;
      });
      await mount(tempDir, "rw");
      executable = process.execPath;
      executableArgs = [bridgePath, socketPath, input.executable, ...input.args];
      cleanup = async () => {
        await proxy.close();
        await fs.rm(tempDir, { recursive: true, force: true });
      };
    }
  } else {
    args.push("--bind", "/", "/");
    if (networkScope === "allowlist") {
      const tempDir = await createNetworkProxyTempDir();
      const socketPath = path.join(tempDir, "proxy.sock");
      const bridgePath = path.join(tempDir, "bridge.cjs");
      await fs.writeFile(bridgePath, await createNetworkProxyBridge(), { mode: 0o500 });
      const proxy = await startNetworkAllowlistProxy(
        input.options.networkAllowlist ?? [],
        input.options.networkTrustedUrls ?? [],
        socketPath,
      ).catch(async (error) => {
        await fs.rm(tempDir, { recursive: true, force: true });
        throw error;
      });
      executable = process.execPath;
      executableArgs = [bridgePath, socketPath, input.executable, ...input.args];
      cleanup = async () => {
        await proxy.close();
        await fs.rm(tempDir, { recursive: true, force: true });
      };
    }
  }

  if (networkScope) {
    args.push("--unshare-net");
    for (const key of PROXY_ENV_KEYS) env[key] = undefined;
    env.NO_PROXY = "";
    env.no_proxy = "";
  }
  if (networkScope === "allowlist") {
    const proxyUrl = `http://127.0.0.1:${SANDBOX_PROXY_PORT}`;
    env.HTTP_PROXY = proxyUrl;
    env.HTTPS_PROXY = proxyUrl;
    env.http_proxy = proxyUrl;
    env.https_proxy = proxyUrl;
  }

  args.push("--chdir", cwd, "--", executable, ...executableArgs);
  return { command: bwrapCommand, args, cwd: "/", env, cleanup };
}

export function parseLocalProcessSandboxExtraPaths(value: unknown): LocalProcessSandboxPath[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry, index) => {
    if (typeof entry === "string") {
      return { path: normalizeAbsolutePath(entry, `filesystemExtraPaths[${index}]`), access: "ro" };
    }
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`filesystemExtraPaths[${index}] must be an absolute path or { path, access } object.`);
    }
    const raw = entry as Record<string, unknown>;
    const access = raw.access === "rw" ? "rw" : raw.access === "ro" || raw.access == null ? "ro" : null;
    if (!access || typeof raw.path !== "string") {
      throw new Error(`filesystemExtraPaths[${index}] must use access "ro" or "rw" and an absolute path.`);
    }
    return { path: normalizeAbsolutePath(raw.path, `filesystemExtraPaths[${index}].path`), access };
  });
}

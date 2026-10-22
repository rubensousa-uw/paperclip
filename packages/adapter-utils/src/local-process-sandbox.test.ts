import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildLocalProcessSandboxSpawnTarget,
  parseLocalProcessFilesystemScope,
  parseLocalProcessNetworkAllowlist,
  parseLocalProcessNetworkScope,
  parseLocalProcessSandboxExtraPaths,
} from "./local-process-sandbox.js";
import * as sandboxModule from "./local-process-sandbox.js";
import { runChildProcess } from "./server-utils.js";
import { spawn } from "node:child_process";

const cleanup: string[] = [];

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

afterEach(async () => {
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
  });

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

/**
 * ATDD (red) for the Factory v7 story 2.9, patch 2 (`feat(codex-local): network sandbox on SSH
 * execution targets`). On an SSH target the allowlist proxy runs ON the target, placed by the
 * remote prepare as a self-contained script. Contract asserted here:
 * `buildRemoteNetworkAllowlistProxyScript({ networkAllowlist, networkTrustedUrls }) => string`
 * returns Node.js source that only imports `node:` built-ins and, run as
 * `node <script> <unixSocketPath>`, serves the same policy as the local proxy
 * (CONNECT to a host outside the list → 403 `network_target_denied`).
 */
describe("remote network allowlist proxy script", () => {
  const build = (sandboxModule as Record<string, unknown>).buildRemoteNetworkAllowlistProxyScript as
    | ((input: { networkAllowlist: string[]; networkTrustedUrls?: string[] }) => string)
    | undefined;

  async function startScript(allowlist: string[]) {
    expect(typeof build).toBe("function");
    const source = build!({ networkAllowlist: allowlist, networkTrustedUrls: [] });
    const dir = await fs.mkdtemp(path.join("/tmp", "pcp-rproxy-"));
    cleanup.push(dir);
    const scriptPath = path.join(dir, "proxy.mjs");
    const socketPath = path.join(dir, "proxy.sock");
    await fs.writeFile(scriptPath, source, "utf8");
    const child = spawn(process.execPath, [scriptPath, socketPath], { stdio: "ignore" });
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (await fs.stat(socketPath).then(() => true, () => false)) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return { source, socketPath, stop: () => child.kill("SIGKILL") };
  }

  function connectThrough(socketPath: string, target: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = net.connect(socketPath);
      let received = "";
      socket.on("data", (chunk) => {
        received += chunk.toString("utf8");
        if (received.startsWith("HTTP/1.1 200") && received.includes("\r\n\r\n")) {
          socket.destroy();
          resolve(received);
        }
      });
      socket.on("error", reject);
      socket.on("close", () => resolve(received));
      socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
    });
  }

  it("is self-contained: only node: built-ins", async () => {
    expect(typeof build).toBe("function");
    const source = build!({ networkAllowlist: ["api.openai.com"], networkTrustedUrls: [] });
    const specifiers = [
      ...source.matchAll(/\bfrom\s+["']([^"']+)["']/g),
      ...source.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g),
      ...source.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g),
    ].map((match) => match[1]);
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) expect(specifier.startsWith("node:")).toBe(true);
  });

  it.runIf(process.platform === "linux")("denies a host outside the allowlist and allows a listed one", async () => {
    const upstream = net.createServer((socket) => socket.end());
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", () => resolve()));
    const port = (upstream.address() as net.AddressInfo).port;
    const proxy = await startScript([`127.0.0.1:${port}`]);
    try {
      const denied = await connectThrough(proxy.socketPath, "denied.example:443");
      expect(denied).toMatch(/^HTTP\/1\.1 403/);
      expect(denied).toContain("network_target_denied");
      const allowed = await connectThrough(proxy.socketPath, `127.0.0.1:${port}`);
      expect(allowed).toMatch(/^HTTP\/1\.1 200/);
    } finally {
      proxy.stop();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });
});

/**
 * Review of 9150f1222 (MEDIUM): an explicit port means that port only, default ports included;
 * no port still means any port. Before: `new URL("https://host:443").port` is "" so `host:443`
 * normalised to "any port" (local-process-sandbox.ts:133).
 */
describe("explicit allowlist ports", () => {
  const build = (sandboxModule as Record<string, unknown>).buildRemoteNetworkAllowlistProxyScript as
    | ((input: { networkAllowlist: string[]; networkTrustedUrls?: string[] }) => string)
    | undefined;

  it("keeps an explicit default port in the normalised allowlist", () => {
    expect(parseLocalProcessNetworkAllowlist(["example.com:443", "example.org:80", "example.net"]))
      .toEqual(["example.com:443", "example.org:80", "example.net"]);
  });

  it.runIf(process.platform === "linux")("an explicit :443 denies another port through the real proxy", async () => {
    expect(typeof build).toBe("function");
    const upstream = net.createServer((socket) => socket.end());
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", () => resolve()));
    const port = (upstream.address() as net.AddressInfo).port;
    const dir = await fs.mkdtemp(path.join("/tmp", "pcp-port-"));
    cleanup.push(dir);
    const scriptPath = path.join(dir, "proxy.mjs");
    const socketPath = path.join(dir, "proxy.sock");
    await fs.writeFile(scriptPath, build!({ networkAllowlist: ["127.0.0.1:443"], networkTrustedUrls: [] }), "utf8");
    const child = spawn(process.execPath, [scriptPath, socketPath], { stdio: "ignore" });
    try {
      for (let attempt = 0; attempt < 100; attempt += 1) {
        if (await fs.stat(socketPath).then(() => true, () => false)) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      const response = await new Promise<string>((resolve, reject) => {
        const socket = net.connect(socketPath);
        let received = "";
        socket.on("data", (chunk) => { received += chunk.toString("utf8"); });
        socket.on("error", reject);
        socket.on("close", () => resolve(received));
        setTimeout(() => socket.destroy(), 2000);
        socket.write(`CONNECT 127.0.0.1:${port} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`);
      });
      expect(response).toMatch(/^HTTP\/1\.1 403/);
      expect(response).toContain("network_target_denied");
    } finally {
      child.kill("SIGKILL");
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    }
  });
});

/**
 * Review of 9150f1222: the remote proxy must be explicit source, like the bridge
 * (`createNetworkProxyBridge`), not `Function.prototype.toString()` of module functions
 * (local-process-sandbox.ts:340). Why: toString returns whatever the toolchain emitted for
 * those functions — after a bundler or esbuild `keepNames` it can reference helpers such as
 * `__name` that do not exist in the standalone script, and renaming a module function changes the
 * shipped program. Asserted statically on the module source and on the generated output.
 */
describe("remote proxy script is an explicit template", () => {
  it("does not serialise module functions", async () => {
    const source = await fs.readFile(new URL("./local-process-sandbox.ts", import.meta.url), "utf8");
    const start = source.indexOf("export function buildRemoteNetworkAllowlistProxyScript");
    expect(start).toBeGreaterThanOrEqual(0);
    const end = source.indexOf("\n}\n", start);
    const body = source.slice(start, end);
    expect(body).not.toMatch(/\.toString\(\)/);
  });

  it("emits no toolchain helpers", () => {
    const build = (sandboxModule as Record<string, unknown>).buildRemoteNetworkAllowlistProxyScript as
      (input: { networkAllowlist: string[]; networkTrustedUrls?: string[] }) => string;
    const script = build({ networkAllowlist: ["api.openai.com"], networkTrustedUrls: [] });
    for (const helper of ["__name(", "__defProp", "__publicField", "_ts_decorate"]) {
      expect(script).not.toContain(helper);
    }
  });
});

/**
 * Re-review of 796f09775 (LOW): one request matrix run against the local matcher and the remote
 * proxy template, so the two policies cannot drift. The local matcher (`isNetworkTargetAllowed`,
 * internal today) is exposed for this as
 * `isNetworkTargetAllowedByPolicy({ networkAllowlist, networkTrustedUrls }, hostname, port)`.
 * The remote side is the real generated proxy run with node: a 403 `network_target_denied` is a
 * denial; any other answer (200, 502 when the upstream is unreachable) means the policy allowed it.
 */
describe("allowlist parity between the local matcher and the remote proxy", () => {
  const POLICY = {
    networkAllowlist: ["api.example.test", "exact.example.test:8443", "default.example.test:443"],
    networkTrustedUrls: ["http://127.0.0.1:4310/api"],
  };
  type Request = { form: "connect" | "absolute"; host: string; port: string; expected: "allow" | "deny" };
  const MATRIX: Request[] = [
    { form: "connect", host: "api.example.test", port: "443", expected: "allow" },
    { form: "connect", host: "api.example.test", port: "8443", expected: "allow" },
    { form: "connect", host: "API.EXAMPLE.TEST", port: "443", expected: "allow" },
    { form: "connect", host: "exact.example.test", port: "8443", expected: "allow" },
    { form: "connect", host: "exact.example.test", port: "443", expected: "deny" },
    { form: "connect", host: "default.example.test", port: "443", expected: "allow" },
    { form: "connect", host: "default.example.test", port: "8443", expected: "deny" },
    { form: "connect", host: "other.example.test", port: "443", expected: "deny" },
    { form: "connect", host: "sub.api.example.test", port: "443", expected: "deny" },
    { form: "connect", host: "127.0.0.1", port: "4310", expected: "allow" },
    { form: "connect", host: "127.0.0.1", port: "4311", expected: "deny" },
    { form: "absolute", host: "api.example.test", port: "80", expected: "allow" },
    { form: "absolute", host: "exact.example.test", port: "8443", expected: "allow" },
    { form: "absolute", host: "exact.example.test", port: "80", expected: "deny" },
    { form: "absolute", host: "127.0.0.1", port: "4310", expected: "allow" },
    { form: "absolute", host: "other.example.test", port: "80", expected: "deny" },
  ];

  it("the local matcher decides the matrix", () => {
    const local = (sandboxModule as Record<string, unknown>).isNetworkTargetAllowedByPolicy as
      | ((policy: typeof POLICY, hostname: string, port: string) => boolean)
      | undefined;
    expect(typeof local).toBe("function");
    for (const request of MATRIX) {
      expect({ request, decision: local!(POLICY, request.host.toLowerCase(), request.port) ? "allow" : "deny" })
        .toEqual({ request, decision: request.expected });
    }
  });

  it.runIf(process.platform === "linux")("the remote proxy decides the same matrix", async () => {
    const build = (sandboxModule as Record<string, unknown>).buildRemoteNetworkAllowlistProxyScript as
      (input: { networkAllowlist: string[]; networkTrustedUrls?: string[] }) => string;
    const dir = await fs.mkdtemp(path.join("/tmp", "pcp-parity-"));
    cleanup.push(dir);
    const scriptPath = path.join(dir, "proxy.mjs");
    const socketPath = path.join(dir, "proxy.sock");
    await fs.writeFile(scriptPath, build(POLICY), "utf8");
    const child = spawn(process.execPath, [scriptPath, socketPath], { stdio: "ignore" });
    try {
      for (let attempt = 0; attempt < 100; attempt += 1) {
        if (await fs.stat(socketPath).then(() => true, () => false)) break;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      for (const request of MATRIX) {
        const head = request.form === "connect"
          ? `CONNECT ${request.host}:${request.port} HTTP/1.1\r\nHost: ${request.host}:${request.port}\r\n\r\n`
          : `GET http://${request.host}${request.port === "80" ? "" : `:${request.port}`}/api/x HTTP/1.1\r\n`
            + `Host: ${request.host}\r\nConnection: close\r\n\r\n`;
        const response = await new Promise<string>((resolve) => {
          const socket = net.connect(socketPath);
          let received = "";
          const done = () => { socket.destroy(); resolve(received); };
          socket.on("data", (chunk) => {
            received += chunk.toString("utf8");
            if (received.includes("\r\n")) done();
          });
          socket.on("error", done);
          socket.on("close", done);
          setTimeout(done, 1500);
          socket.write(head);
        });
        const decision = /^HTTP\/1\.1 403/.test(response) ? "deny" : "allow";
        expect({ request, decision }).toEqual({ request, decision: request.expected });
      }
    } finally {
      child.kill("SIGKILL");
    }
  }, 60_000);
});

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  linkedWorkspaceVersion,
  materializePublishManifest,
  stripStagedLifecycleScripts,
} from "./prepare-bundled-package.mjs";

// Git-ref installs (`paperclipai install --ref`) stage bundled packages from a
// checkout whose workspace packages keep their own checked-in versions (#15026).

test("workspace dependencies keep the dependent's version unless a resolver names their own", () => {
  const pkg = {
    name: "@paperclipai/server",
    version: "0.3.1",
    dependencies: {
      "@paperclipai/plugin-sdk": "workspace:*",
      "@paperclipai/shared": "workspace:^",
      leftpad: "1.0.0",
    },
  };
  assert.deepEqual(materializePublishManifest(pkg).dependencies, {
    "@paperclipai/plugin-sdk": "0.3.1",
    "@paperclipai/shared": "^0.3.1",
    leftpad: "1.0.0",
  });
  const versions = { "@paperclipai/plugin-sdk": "1.0.0" };
  assert.deepEqual(
    materializePublishManifest(pkg, { workspaceVersion: (name) => versions[name] ?? null }).dependencies,
    {
      "@paperclipai/plugin-sdk": "1.0.0",
      "@paperclipai/shared": "^0.3.1",
      leftpad: "1.0.0",
    },
  );
});

test("linkedWorkspaceVersion reads the linked package's own version and returns null when absent", () => {
  const sourceDir = mkdtempSync(join(tmpdir(), "paperclip-linked-version-"));
  try {
    const linked = join(sourceDir, "node_modules", "@paperclipai", "plugin-sdk");
    mkdirSync(linked, { recursive: true });
    writeFileSync(join(linked, "package.json"), JSON.stringify({ name: "@paperclipai/plugin-sdk", version: "1.0.0" }));
    assert.equal(linkedWorkspaceVersion(sourceDir, "@paperclipai/plugin-sdk"), "1.0.0");
    assert.equal(linkedWorkspaceVersion(sourceDir, "@paperclipai/missing"), null);
  } finally {
    rmSync(sourceDir, { recursive: true, force: true });
  }
});

test("staged manifests drop the lifecycle scripts that would rebuild from the workspace", () => {
  const manifest = {
    scripts: {
      build: "tsc",
      prepack: "pnpm run prepare:ui-dist && pnpm run build",
      postpack: "rm -rf ui-dist",
      prepare: "x",
      prepublishOnly: "y",
      start: "node dist/index.js",
    },
  };
  assert.deepEqual(stripStagedLifecycleScripts(manifest).scripts, {
    build: "tsc",
    start: "node dist/index.js",
  });
  assert.deepEqual(stripStagedLifecycleScripts({ name: "x" }), { name: "x" });
});

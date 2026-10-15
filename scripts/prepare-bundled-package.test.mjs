import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  linkedWorkspaceVersion,
  materializePublishManifest,
  prepareBundledPackage,
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

test("prepareBundledPackage writes the staged manifest and copies the build-npm payload", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "paperclip-bundled-package-"));
  const previousPath = process.env.PATH;
  try {
    const sourceRoot = join(tempRoot, "repo");
    const fakeBin = join(tempRoot, "bin");
    mkdirSync(join(sourceRoot, "scripts"), { recursive: true });
    mkdirSync(fakeBin, { recursive: true });
    writeFileSync(join(sourceRoot, "package.json"), JSON.stringify({ pnpm: { patchedDependencies: {} } }));
    const npmStub = join(fakeBin, "npm");
    writeFileSync(npmStub, "#!/bin/sh\nexit 0\n");
    chmodSync(npmStub, 0o755);

    const skillsRoot = join(sourceRoot, "skills");
    mkdirSync(skillsRoot, { recursive: true });
    writeFileSync(join(skillsRoot, "fixture-skill.md"), "skill payload\n");
    writeFileSync(
      join(sourceRoot, "scripts", "prepare-server-ui-dist.sh"),
      "#!/bin/sh\nmkdir -p \"$REPO_ROOT/server/ui-dist\"\nprintf '%s\\n' '<html>server UI</html>' > \"$REPO_ROOT/server/ui-dist/index.html\"\n",
    );

    const packageSpecs = [
      {
        relativePath: "server",
        name: "@paperclipai/server",
        files: ["dist", "ui-dist", "skills"],
        scripts: {
          prepack: "rebuild from workspace",
          postpack: "clean workspace output",
          prepare: "rebuild from workspace",
          prepublishOnly: "rebuild from workspace",
          start: "node dist/index.js",
        },
        dependencies: { "@paperclipai/plugin-sdk": "workspace:*" },
      },
      {
        relativePath: "packages/adapters/claude-local",
        name: "@paperclipai/adapter-claude-local",
        files: ["dist", "skills"],
      },
      {
        relativePath: "packages/adapters/codex-local",
        name: "@paperclipai/adapter-codex-local",
        files: ["dist", "skills"],
      },
    ];
    for (const spec of packageSpecs) {
      const sourceDir = join(sourceRoot, spec.relativePath);
      mkdirSync(sourceDir, { recursive: true });
      mkdirSync(join(sourceDir, "dist"), { recursive: true });
      writeFileSync(join(sourceDir, "dist", "index.js"), `${spec.name} build\n`);
      writeFileSync(
        join(sourceDir, "package.json"),
        JSON.stringify({
          name: spec.name,
          version: "0.3.1",
          files: spec.files,
          bundleDependencies: ["fixture-bundle"],
          ...(spec.scripts ? { scripts: spec.scripts } : {}),
          ...(spec.dependencies ? { dependencies: spec.dependencies } : {}),
        }),
      );
    }
    const linkedSdk = join(sourceRoot, "server", "node_modules", "@paperclipai", "plugin-sdk");
    mkdirSync(linkedSdk, { recursive: true });
    writeFileSync(join(linkedSdk, "package.json"), JSON.stringify({ name: "@paperclipai/plugin-sdk", version: "1.0.0" }));

    const buildScript = readFileSync(new URL("./build-npm.sh", import.meta.url), "utf8");
    const start = buildScript.indexOf('echo "  [5b/6]');
    const end = buildScript.indexOf("\n# ── Step 6:", start);
    assert.ok(start >= 0 && end > start, "build-npm.sh must contain its Step 5b payload staging block");
    const stageBlock = buildScript.slice(start, end);
    process.env.PATH = `${fakeBin}${delimiter}${previousPath ?? ""}`;
    execFileSync("bash", ["-c", stageBlock], { cwd: sourceRoot, env: { ...process.env, REPO_ROOT: sourceRoot } });

    const serverStage = join(tempRoot, "staged", "server");
    const claudeStage = join(tempRoot, "staged", "claude-local");
    const codexStage = join(tempRoot, "staged", "codex-local");
    prepareBundledPackage(join(sourceRoot, "server"), serverStage, { sourceRoot });
    prepareBundledPackage(join(sourceRoot, "packages/adapters/claude-local"), claudeStage, { sourceRoot });
    prepareBundledPackage(join(sourceRoot, "packages/adapters/codex-local"), codexStage, { sourceRoot });

    const stagedManifest = JSON.parse(readFileSync(join(serverStage, "package.json"), "utf8"));
    assert.equal(stagedManifest.version, "0.3.1");
    assert.equal(stagedManifest.dependencies["@paperclipai/plugin-sdk"], "1.0.0");
    for (const script of ["prepack", "postpack", "prepare", "prepublishOnly"]) {
      assert.equal(script in stagedManifest.scripts, false, `${script} must be removed from the staged manifest`);
    }
    assert.equal(readFileSync(join(serverStage, "ui-dist", "index.html"), "utf8"), "<html>server UI</html>\n");
    assert.equal(readFileSync(join(serverStage, "skills", "fixture-skill.md"), "utf8"), "skill payload\n");
    assert.equal(readFileSync(join(claudeStage, "skills", "fixture-skill.md"), "utf8"), "skill payload\n");
    assert.equal(readFileSync(join(codexStage, "skills", "fixture-skill.md"), "utf8"), "skill payload\n");
  } finally {
    process.env.PATH = previousPath;
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

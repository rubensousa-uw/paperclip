/**
 * Re-review of 796f09775 (HIGH): the host-side git commands that operate on the remote
 * workspace (SSH import/export/restore scripts, e.g. `ssh.ts:862` `update-ref`, `bundle create`,
 * the cleanup `update-ref -d`, and the restore scripts in `git-workspace-sync.ts`) run OUTSIDE the
 * confinement on a `.git` the confined agent can write (it stays writable because agents commit).
 * Decision: every such command carries `-c core.hooksPath=/dev/null -c core.fsmonitor=false`, so
 * the host never runs repo-controlled hooks or fsmonitor.
 *
 * Asserted on the script builders' source: each shell `git … -C <dir>` command segment must carry
 * both overrides. A shared helper that emits them (and leaves no bare `git -C` behind) passes.
 * Local `runLocalGit` (argv array on the controller's own checkout) is out of scope.
 */
import fs from "node:fs/promises";
import { describe, expect, it } from "vitest";

const FILES = ["./ssh.ts", "./git-workspace-sync.ts"];

function bareRemoteGitCommands(source: string): string[] {
  const offenders: string[] = [];
  for (const line of source.split("\n")) {
    for (const segment of line.split(/\|\||&&|;|\|(?!\|)/)) {
      if (!/\bgit\s+(?:-c\s+\S+\s+)*-C\s/.test(segment)) continue;
      if (segment.includes("core.hooksPath=/dev/null") && segment.includes("core.fsmonitor=false")) continue;
      offenders.push(segment.trim());
    }
  }
  return offenders;
}

describe("host-side git on the remote workspace ignores repo hooks and fsmonitor", () => {
  for (const file of FILES) {
    it(`${file}: no bare git -C in remote scripts`, async () => {
      const source = await fs.readFile(new URL(file, import.meta.url), "utf8");
      expect(bareRemoteGitCommands(source)).toEqual([]);
    });
  }

  it("the scanner itself flags a bare command and accepts a hardened one", () => {
    expect(bareRemoteGitCommands("`git -C ${dir} update-ref x HEAD`")).toHaveLength(1);
    expect(bareRemoteGitCommands(
      "`git -C ${dir} -c core.hooksPath=/dev/null -c core.fsmonitor=false update-ref x HEAD`",
    )).toEqual([]);
  });
});

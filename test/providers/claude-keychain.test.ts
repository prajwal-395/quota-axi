import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const execFileText = vi.fn();
vi.mock("../../src/lib/process.js", () => ({ execFileText }));
const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
const options = { allowKeychainPrompt: true, refreshCredentials: false };
const service = "Claude Code-credentials";
const keychainCall = { abandonOnTimeout: true };
let home: string;

beforeEach(() => {
  vi.resetModules();
  execFileText.mockReset();
  home = mkdtempSync(join(tmpdir(), "quota-axi-keychain-"));
  vi.stubEnv("HOME", home);
  vi.stubEnv("USERPROFILE", home);
  vi.stubEnv("XDG_CACHE_HOME", join(home, "cache"));
  vi.stubEnv("USER", "fixture-user");
  vi.stubEnv("CLAUDE_CONFIG_DIR", undefined);
  vi.stubEnv("CLAUDE_SECURESTORAGE_CONFIG_DIR", undefined);
  Object.defineProperty(process, "platform", { value: "darwin" });
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify({ five_hour: { utilization: 12 } })),
    ),
  );
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  Object.defineProperty(process, "platform", platform);
  rmSync(home, { recursive: true, force: true });
});

function cachedClaude() {
  return {
    provider: "claude" as const,
    label: "Claude",
    source: "oauth",
    windows: [
      {
        id: "five_hour",
        label: "session",
        kind: "session" as const,
        percentUsed: 12,
      },
    ],
    state: {
      status: "fresh" as const,
      stale: false,
      refreshedAt: "2026-09-13T00:30:00Z",
      sourcesTried: ["oauth"],
    },
  };
}

function valueReadArgs(): string[] {
  const call = execFileText.mock.calls.find(([, args]: [string, string[]]) =>
    args.includes("-w"),
  );
  return (call?.[1] ?? []) as string[];
}

function profileService(configDir: string): string {
  return `${service}-${createHash("sha256")
    .update(configDir.normalize("NFC"))
    .digest("hex")
    .slice(0, 8)}`;
}

function unreachable(): Error {
  return Object.assign(new Error("synthetic item unavailable"), { code: 44 });
}

/** A synthetic store holding only `readableService` for the fixture account. */
function mockItems(readableService = service): void {
  execFileText.mockImplementation(async (command: string, args: string[]) => {
    expect(command).toBe("security");
    expect(args.slice(0, 3)).toEqual([
      "find-generic-password",
      "-a",
      "fixture-user",
    ]);
    if (!args.includes(readableService)) throw unreachable();
    return args.includes("-w")
      ? JSON.stringify({ claudeAiOauth: { accessToken: "synthetic-token" } })
      : "";
  });
}

function grantMarker(granted = service): Promise<void> {
  return import("../../src/lib/fs.js").then(
    ({ claudeKeychainAccessMarkerPath }) => {
      const marker = claudeKeychainAccessMarkerPath("fixture-user", granted);
      mkdirSync(dirname(marker), { recursive: true });
      writeFileSync(marker, "granted\n", { mode: 0o600 });
    },
  );
}

describe("Claude macOS Keychain exact lookup", () => {
  it("still reads a legacy unsuffixed item", async () => {
    mockItems("Claude Code-credentials");
    const { fetchQuota } = await import("../../src/providers/claude.js");
    expect((await fetchQuota(options)).state.status).toBe("fresh");
  });

  it("reads only the exact selected service, never another Claude item", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-13T01:00:00Z"));
    // Only an opaque-suffixed item is readable; the default profile names the
    // unsuffixed service and no dump enumerates the store to find another.
    mockItems("Claude Code-credentials-abcdef12");
    const { readCachedProvider, writeCachedProviders } =
      await import("../../src/cache.js");
    writeCachedProviders([cachedClaude()]);
    const { fetchQuota } = await import("../../src/providers/claude.js");
    const report = await fetchQuota(options);

    expect(report.state).toMatchObject({
      status: "stale",
      error: "keychain_unreachable",
    });
    expect(readCachedProvider("claude")).toBeDefined();
    expect(execFileText.mock.calls).toEqual([
      [
        "security",
        ["find-generic-password", "-a", "fixture-user", "-w", "-s", service],
        60000,
        keychainCall,
      ],
    ]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("never opens the default profile's item for an explicit profile", async () => {
    const explicitDir = join(home, "explicit-profile");
    vi.stubEnv("CLAUDE_CONFIG_DIR", explicitDir);
    mockItems(service);
    const { fetchQuota } = await import("../../src/providers/claude.js");
    const report = await fetchQuota(options);

    expect(report.state.status).not.toBe("auth_required");
    expect(valueReadArgs()).toContain(profileService(explicitDir));
    expect(valueReadArgs()).not.toContain(service);
    expect(execFileText).toHaveBeenCalledTimes(1);
  });

  it("reads the suffix selected by Claude secure storage in one exact call", async () => {
    const configDir = "/fixture/secure-profile";
    const selectedService = profileService(configDir);
    vi.stubEnv("CLAUDE_SECURESTORAGE_CONFIG_DIR", configDir);
    mockItems(selectedService);
    const { fetchQuota } = await import("../../src/providers/claude.js");
    const report = await fetchQuota(options);

    expect(report.state.status).toBe("fresh");
    expect(report.windows).toMatchObject([
      { id: "five_hour", percentUsed: 12 },
    ]);
    expect(execFileText.mock.calls).toEqual([
      [
        "security",
        [
          "find-generic-password",
          "-a",
          "fixture-user",
          "-w",
          "-s",
          selectedService,
        ],
        60000,
        keychainCall,
      ],
    ]);
    expect(JSON.stringify(report)).not.toContain("synthetic-token");
    expect(JSON.stringify(report)).not.toContain("fixture-user");
  });

  it("checks presence with one value-free lookup until the grant policy permits a read", async () => {
    mockItems();
    const { inspectAuth } = await import("../../src/providers/claude.js");
    const auth = await inspectAuth({ ...options, allowKeychainPrompt: false });
    expect(auth.sources).toContainEqual({
      source: "keychain",
      status: "skipped",
      error: "keychain_prompt_required",
      credentialPresent: true,
    });
    expect(execFileText.mock.calls).toEqual([
      [
        "security",
        ["find-generic-password", "-a", "fixture-user", "-s", service],
        5000,
        keychainCall,
      ],
    ]);

    execFileText.mockClear();
    await grantMarker();
    const granted = await inspectAuth({
      ...options,
      allowKeychainPrompt: false,
    });
    expect(granted.sources).toContainEqual({
      source: "keychain",
      status: "available",
    });
    // The grant reads the value directly, with no presence lookup beside it.
    expect(execFileText).toHaveBeenCalledTimes(1);
    expect(valueReadArgs()).toContain(service);
  });

  it("never invokes a whole-keychain listing", async () => {
    mockItems();
    const { fetchQuota, inspectAuth } =
      await import("../../src/providers/claude.js");
    await inspectAuth({ ...options, allowKeychainPrompt: false });
    await fetchQuota({ ...options, allowKeychainPrompt: false });
    await fetchQuota(options);
    for (const [, args] of execFileText.mock.calls as [string, string[]][]) {
      expect(args[0]).toBe("find-generic-password");
      expect(args).not.toContain("dump-keychain");
      expect(args).not.toContain("list-keychains");
    }
  });

  it("reuses a granted Keychain reading across back-to-back reads with --max-age", async () => {
    mockItems();
    await grantMarker();
    const { quotaCommand } = await import("../../src/commands.js");

    for (let read = 0; read < 3; read++) {
      const output = await quotaCommand(
        [
          "--provider",
          "claude",
          "--json",
          "--no-credential-refresh",
          "--max-age",
          "90s",
        ],
        undefined,
      );
      expect(JSON.parse(output).providers[0].state.status).toBe("fresh");
    }
    expect(
      vi
        .mocked(fetch)
        .mock.calls.filter(([url]) => String(url).endsWith("/api/oauth/usage")),
    ).toHaveLength(1);
  });

  it.each([false, true])(
    "keeps an ambiguous exit 44 as unreachable without asserting absence (prompt=%s)",
    async (allowKeychainPrompt) => {
      execFileText.mockRejectedValue(unreachable());
      const { inspectAuth } = await import("../../src/providers/claude.js");
      const auth = await inspectAuth({ ...options, allowKeychainPrompt });
      expect(auth.sources).toContainEqual(
        expect.objectContaining({
          source: "keychain",
          status: "skipped",
          error: "keychain_unreachable",
        }),
      );
      expect(auth.sources).not.toContainEqual(
        expect.objectContaining({ source: "keychain", status: "missing" }),
      );
      expect(execFileText).toHaveBeenCalledTimes(1);
    },
  );

  it.each([
    ["denied", { code: 51 }, "keychain_access_denied"],
    ["timeout", { killed: true, signal: "SIGTERM" }, "keychain_prompt_timeout"],
    [
      "abandoned",
      { abandoned: true, code: "ETIMEDOUT" },
      "keychain_prompt_timeout",
    ],
    ["unreachable", { code: 44 }, "keychain_unreachable"],
  ])(
    "does not cross profiles after a %s value read",
    async (_label, failure, error) => {
      execFileText.mockRejectedValue(
        Object.assign(new Error("read failed"), failure),
      );
      const { inspectAuth } = await import("../../src/providers/claude.js");
      expect((await inspectAuth(options)).sources).toContainEqual({
        source: "keychain",
        status: "skipped",
        error,
        credentialPresent: true,
      });
      expect(execFileText).toHaveBeenCalledTimes(1);
      expect(valueReadArgs()).toContain(service);
    },
  );

  it("reports a presence lookup that outlived its wait as unchecked, not absent", async () => {
    execFileText.mockRejectedValue(
      Object.assign(new Error("left running"), {
        abandoned: true,
        code: "ETIMEDOUT",
      }),
    );
    const { inspectAuth } = await import("../../src/providers/claude.js");
    const auth = await inspectAuth({ ...options, allowKeychainPrompt: false });
    expect(auth.sources).toContainEqual({
      source: "keychain",
      status: "skipped",
      error: "keychain_presence_check_failed",
    });
    expect(execFileText.mock.calls).toEqual([
      [
        "security",
        ["find-generic-password", "-a", "fixture-user", "-s", service],
        5000,
        keychainCall,
      ],
    ]);
  });

  it("detects a sign-in on a later read in the same process", async () => {
    let signedIn = false;
    execFileText.mockImplementation(async () => {
      if (!signedIn) throw unreachable();
      return JSON.stringify({
        claudeAiOauth: { accessToken: "synthetic-token" },
      });
    });
    const { fetchQuota } = await import("../../src/providers/claude.js");

    expect((await fetchQuota(options)).state.error).toBe(
      "keychain_unreachable",
    );
    signedIn = true;
    expect((await fetchQuota(options)).state.status).toBe("fresh");
  });

  it("reselects a changed secure-storage profile without transferring its prompt grant", async () => {
    const firstProfile = "/fixture/tui-first-profile";
    const nextProfile = "/fixture/tui-next-profile";
    const firstService = profileService(firstProfile);
    const nextService = profileService(nextProfile);
    vi.stubEnv("CLAUDE_SECURESTORAGE_CONFIG_DIR", firstProfile);
    mockItems(firstService);
    const { fetchQuota } = await import("../../src/providers/claude.js");
    expect((await fetchQuota(options)).state.status).toBe("fresh");

    vi.stubEnv("CLAUDE_SECURESTORAGE_CONFIG_DIR", nextProfile);
    mockItems(nextService);
    const withheld = await fetchQuota({
      ...options,
      allowKeychainPrompt: false,
    });
    expect(withheld.state).toMatchObject({
      status: "auth_required",
      error: "keychain_prompt_required",
    });
    expect(withheld.attempts).toContainEqual(
      expect.objectContaining({
        source: "keychain",
        status: "skipped",
        error: "keychain_prompt_required",
      }),
    );
    expect(
      execFileText.mock.calls.filter(([, args]) => args.includes("-w")),
    ).toHaveLength(1);

    expect((await fetchQuota(options)).state.status).toBe("fresh");
    const reads = execFileText.mock.calls.filter(([, args]) =>
      args.includes("-w"),
    );
    expect(reads.map(([, args]) => args[args.indexOf("-s") + 1])).toEqual([
      firstService,
      nextService,
    ]);
  });
  it("withholds a snapshot from the former opaque-discovery context without deleting it", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-13T01:00:00Z"));
    mockItems("unavailable-service");
    const { cacheFilePath } = await import("../../src/lib/fs.js");
    const file = cacheFilePath();
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(
      file,
      JSON.stringify({
        schemaVersion: 2,
        providers: [
          {
            ...cachedClaude(),
            credentialContext: createHash("sha256")
              .update(`claude-config-dir:${join(home, ".claude")}`)
              .digest("hex"),
          },
        ],
      }),
      { mode: 0o600 },
    );
    const { readCachedProvider } = await import("../../src/cache.js");
    const { fetchQuota } = await import("../../src/providers/claude.js");
    const report = await fetchQuota(options);

    expect(report.state.status).not.toBe("stale");
    expect(report.windows).toEqual([]);
    expect(readCachedProvider("claude")?.windows).toEqual(
      cachedClaude().windows,
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("keeps cached quota when a located item is unread and a leftover file is rejected", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-13T01:00:00Z"));
    mkdirSync(join(home, ".claude"));
    writeFileSync(
      join(home, ".claude", ".credentials.json"),
      JSON.stringify({
        claudeAiOauth: {
          accessToken: "synthetic-rejected-token",
          expiresAt: 0,
        },
      }),
    );
    mockItems();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 401 })),
    );
    const { readCachedProvider, writeCachedProviders } =
      await import("../../src/cache.js");
    writeCachedProviders([cachedClaude()]);
    const { fetchQuota } = await import("../../src/providers/claude.js");
    const report = await fetchQuota({ ...options, allowKeychainPrompt: false });

    expect(report.state).toMatchObject({
      status: "stale",
      error: "keychain_prompt_required",
    });
    expect(report.source).toBe("cache");
    expect(readCachedProvider("claude")).toBeDefined();
    expect(valueReadArgs()).toEqual([]);
  });

  it("keeps an unchecked Keychain visible behind the file credential that answered", async () => {
    mkdirSync(join(home, ".claude"));
    writeFileSync(
      join(home, ".claude", ".credentials.json"),
      JSON.stringify({
        claudeAiOauth: {
          accessToken: "synthetic-file-token",
          expiresAt: Date.parse("2035-01-01T00:00:00Z"),
        },
      }),
    );
    execFileText.mockRejectedValue(
      Object.assign(new Error("listing failed"), {
        code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      }),
    );
    const chunks: string[] = [];
    const { main } = await import("../../src/cli.js");
    await main({
      argv: ["--provider", "claude", "--no-credential-refresh"],
      binPath: "quota-axi",
      stdout: {
        write(chunk) {
          chunks.push(String(chunk));
          return true;
        },
      },
    });

    expect(chunks.join("")).toContain(
      "claude,all,degraded_source,keychain · keychain_presence_check_failed,none",
    );
  });

  it.each([
    ["unreachable", { code: 44 }, "keychain_unreachable"],
    ["timeout", { killed: true, signal: "SIGTERM" }, "keychain_prompt_timeout"],
    [
      "abandoned",
      { abandoned: true, code: "ETIMEDOUT" },
      "keychain_prompt_timeout",
    ],
    [
      "buffer limit",
      { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" },
      "keychain_access_denied",
    ],
  ])(
    "preserves cached quota after a %s Keychain read and a leftover file's 401",
    async (_label, failure, error) => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-09-13T01:00:00Z"));
      mkdirSync(join(home, ".claude"));
      writeFileSync(
        join(home, ".claude", ".credentials.json"),
        JSON.stringify({
          claudeAiOauth: {
            accessToken: "synthetic-rejected-token",
            expiresAt: 0,
          },
        }),
      );
      execFileText.mockRejectedValue(
        Object.assign(new Error("listing failed"), failure),
      );
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(null, { status: 401 })),
      );
      const { readCachedProvider, writeCachedProviders } =
        await import("../../src/cache.js");
      writeCachedProviders([
        {
          provider: "claude",
          label: "Claude",
          source: "oauth",
          windows: [
            {
              id: "five_hour",
              label: "session",
              kind: "session",
              percentUsed: 12,
            },
          ],
          state: {
            status: "fresh",
            stale: false,
            refreshedAt: "2026-09-13T00:30:00Z",
            sourcesTried: ["oauth"],
          },
        },
      ]);
      const { fetchQuota } = await import("../../src/providers/claude.js");
      const report = await fetchQuota(options);
      expect(report.state).toMatchObject({ status: "stale", error });
      expect(report.source).toBe("cache");
      expect(readCachedProvider("claude")).toBeDefined();
    },
  );
});

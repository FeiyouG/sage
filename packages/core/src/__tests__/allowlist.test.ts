import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { addCommand, addUrl, isAllowlisted, loadAllowlist, saveAllowlist } from "../allowlist.js";
import type { Allowlist, AllowlistConfig, Artifact } from "../types.js";
import { hashCommand } from "../url-utils.js";
import { makeTmpDir } from "./test-utils.js";

function makeConfig(path: string): AllowlistConfig {
	return { path };
}

describe("loadAllowlist", () => {
	it("returns empty for missing file", async () => {
		const al = await loadAllowlist(makeConfig("/nonexistent/allowlist.json"));
		expect(Object.keys(al.urls)).toHaveLength(0);
		expect(Object.keys(al.commands)).toHaveLength(0);
	});

	it("loads valid allowlist", async () => {
		const dir = await makeTmpDir();
		const path = join(dir, "allowlist.json");
		await writeFile(
			path,
			JSON.stringify({
				urls: {
					"http://safe.com": {
						added_at: "2024-01-01T00:00:00Z",
						reason: "false positive",
						original_verdict: "deny",
					},
				},
				commands: {},
			}),
		);
		const al = await loadAllowlist(makeConfig(path));
		// Keys are normalized on load (trailing slash added by URL constructor)
		expect(al.urls["http://safe.com/"]).toBeDefined();
		expect(al.urls["http://safe.com/"]?.reason).toBe("false positive");
	});

	it("returns empty for malformed JSON", async () => {
		const dir = await makeTmpDir();
		const path = join(dir, "allowlist.json");
		await writeFile(path, "not json");
		const al = await loadAllowlist(makeConfig(path));
		expect(Object.keys(al.urls)).toHaveLength(0);
	});
});

describe("saveAllowlist", () => {
	it("saves to disk", async () => {
		const dir = await makeTmpDir();
		const path = join(dir, "allowlist.json");
		const al: Allowlist = {
			urls: {
				"http://test.com": {
					addedAt: "2024-01-01T00:00:00Z",
					reason: "test",
					originalVerdict: "deny",
				},
			},
			commands: {},
		};
		await saveAllowlist(al, makeConfig(path));
		const raw = await readFile(path, "utf-8");
		const data = JSON.parse(raw);
		expect(data.urls["http://test.com"]).toBeDefined();
	});
});

describe("isAllowlisted", () => {
	it("matches URL artifact", () => {
		const al: Allowlist = {
			urls: {
				"http://safe.com/": {
					addedAt: "2024-01-01T00:00:00Z",
					reason: "safe",
					originalVerdict: "deny",
				},
			},
			commands: {},
		};
		const artifacts: Artifact[] = [{ type: "url", value: "http://safe.com" }];
		expect(isAllowlisted(al, artifacts)).toBe(true);
	});

	it("matches command by hash", () => {
		const cmdHash = hashCommand("safe command");
		const al: Allowlist = {
			urls: {},
			commands: {
				[cmdHash]: {
					addedAt: "2024-01-01T00:00:00Z",
					reason: "safe",
					originalVerdict: "deny",
				},
			},
		};
		const artifacts: Artifact[] = [{ type: "command", value: "safe command" }];
		expect(isAllowlisted(al, artifacts)).toBe(true);
	});

	it("returns false when not allowlisted", () => {
		const al: Allowlist = { urls: {}, commands: {} };
		const artifacts: Artifact[] = [{ type: "url", value: "http://unknown.com" }];
		expect(isAllowlisted(al, artifacts)).toBe(false);
	});

	it("matches URL regardless of case", () => {
		const al: Allowlist = {
			urls: {},
			commands: {},
		};
		addUrl(al, "http://safe.com/path", "false positive", "deny");
		const artifacts: Artifact[] = [{ type: "url", value: "HTTP://SAFE.COM/path" }];
		expect(isAllowlisted(al, artifacts)).toBe(true);
	});

	it("matches URL regardless of query parameter order", () => {
		const al: Allowlist = {
			urls: {},
			commands: {},
		};
		addUrl(al, "http://safe.com/path?b=2&a=1", "false positive", "deny");
		const artifacts: Artifact[] = [{ type: "url", value: "http://safe.com/path?a=1&b=2" }];
		expect(isAllowlisted(al, artifacts)).toBe(true);
	});
});

describe("addUrl / addCommand", () => {
	it("adds URL entry with normalized key", () => {
		const al: Allowlist = { urls: {}, commands: {} };
		addUrl(al, "HTTP://NEW.COM/path", "user approved", "deny");
		// Key should be normalized (lowercased, trailing slash for domain)
		expect(al.urls["http://new.com/path"]).toBeDefined();
		expect(al.urls["http://new.com/path"]?.reason).toBe("user approved");
	});

	it("adds command entry by hash", () => {
		const al: Allowlist = { urls: {}, commands: {} };
		addCommand(al, "some command", "user approved", "ask");
		const hash = hashCommand("some command");
		expect(al.commands[hash]).toBeDefined();
	});
});

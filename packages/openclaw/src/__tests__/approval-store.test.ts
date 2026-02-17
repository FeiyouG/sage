import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nullLogger } from "@sage/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";

describe("ApprovalStore", () => {
	let dir: string;
	let path: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-approval-test-"));
		path = join(dir, "approvals.json");
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("load/save round-trip", async () => {
		const store = new ApprovalStore(nullLogger, path);
		await store.load();
		await store.approve("test-action", 60);

		const store2 = new ApprovalStore(nullLogger, path);
		await store2.load();
		expect(store2.isApproved("test-action")).toBe(true);
	});

	it("isApproved returns true for fresh approval", async () => {
		const store = new ApprovalStore(nullLogger, path);
		await store.load();
		await store.approve("abc", 300);
		expect(store.isApproved("abc")).toBe(true);
	});

	it("isApproved returns false after TTL expiry", async () => {
		const store = new ApprovalStore(nullLogger, path);
		await store.load();
		// Approve with 0-second TTL (already expired)
		await store.approve("expired", 0);
		expect(store.isApproved("expired")).toBe(false);
	});

	it("isApproved returns false for unknown action", async () => {
		const store = new ApprovalStore(nullLogger, path);
		await store.load();
		expect(store.isApproved("nonexistent")).toBe(false);
	});

	it("corrupt file → empty store (fail-open)", async () => {
		await writeFile(path, "not valid json!!!");

		const store = new ApprovalStore(nullLogger, path);
		await store.load();
		expect(store.isApproved("anything")).toBe(false);
	});

	it("missing file → empty store", async () => {
		const store = new ApprovalStore(nullLogger, join(dir, "nonexistent.json"));
		await store.load();
		expect(store.isApproved("anything")).toBe(false);
	});

	it("actionId is deterministic for same inputs", () => {
		const id1 = ApprovalStore.actionId("exec", { command: "ls" });
		const id2 = ApprovalStore.actionId("exec", { command: "ls" });
		expect(id1).toBe(id2);
	});

	it("actionId differs for different inputs", () => {
		const id1 = ApprovalStore.actionId("exec", { command: "ls" });
		const id2 = ApprovalStore.actionId("exec", { command: "rm -rf /" });
		expect(id1).not.toBe(id2);
	});

	it("prunes expired entries on load", async () => {
		const data = {
			expired: {
				approvedAt: "2020-01-01T00:00:00.000Z",
				expiresAt: "2020-01-01T00:01:00.000Z",
			},
			fresh: {
				approvedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 60_000).toISOString(),
			},
		};
		await writeFile(path, JSON.stringify(data));

		const store = new ApprovalStore(nullLogger, path);
		await store.load();
		expect(store.isApproved("expired")).toBe(false);
		expect(store.isApproved("fresh")).toBe(true);
	});
});

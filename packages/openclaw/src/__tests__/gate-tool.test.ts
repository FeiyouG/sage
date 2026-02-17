import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nullLogger } from "@sage/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { createSageApproveTool } from "../gate-tool.js";

describe("sage_approve gate tool", () => {
	let dir: string;
	let approvalStore: ApprovalStore;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "sage-gate-test-"));
		approvalStore = new ApprovalStore(nullLogger, join(dir, "approvals.json"));
		await approvalStore.load();
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("approve stores approval and returns success", async () => {
		const tool = createSageApproveTool(approvalStore);
		const result = await tool.execute("call-1", {
			actionId: "test-id",
			approved: true,
		});

		expect(result.content[0]?.text).toBe("Approved. Retry the tool call.");
		expect(approvalStore.isApproved("test-id")).toBe(true);
	});

	it("reject returns rejection message", async () => {
		const tool = createSageApproveTool(approvalStore);
		const result = await tool.execute("call-1", {
			actionId: "test-id",
			approved: false,
		});

		expect(result.content[0]?.text).toBe("Rejected by user.");
		expect(approvalStore.isApproved("test-id")).toBe(false);
	});

	it("tool schema matches expected shape", () => {
		const tool = createSageApproveTool(approvalStore);
		expect(tool.name).toBe("sage_approve");
		expect(tool.description).toBeTruthy();

		const params = tool.parameters as Record<string, unknown>;
		expect(params.type).toBe("object");

		const properties = params.properties as Record<string, Record<string, unknown>>;
		expect(properties.actionId).toBeTruthy();
		expect(properties.approved).toBeTruthy();

		const required = params.required as string[];
		expect(required).toContain("actionId");
		expect(required).toContain("approved");
	});
});

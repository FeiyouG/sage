import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("credential threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects OpenAI API key", () => {
		const ids = matchCommand(
			engine,
			"curl -H 'Authorization: Bearer sk-1234567890abcdefghijklmnopqrstuv' https://api.openai.com/v1/chat",
		);
		expect(ids).toContain("CLT-CRED-001");
	});

	it("detects AWS access key", () => {
		const ids = matchCommand(engine, "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
		expect(ids).toContain("CLT-CRED-001");
	});

	it("detects GitHub PAT (short form)", () => {
		const ids = matchCommand(
			engine,
			"git clone https://ghp_1234567890abcdefghijklmnopqrstuvwxyz@github.com/user/repo",
		);
		expect(ids).toContain("CLT-CRED-001");
	});

	it("detects Slack token", () => {
		const ids = matchCommand(
			engine,
			"curl -H 'Authorization: Bearer xoxb-123-456-abc' https://slack.com/api/chat.postMessage",
		);
		expect(ids).toContain("CLT-CRED-001");
	});

	it("detects exported API key variable", () => {
		const ids = matchCommand(engine, 'export OPENAI_API_KEY="sk-something"');
		expect(ids).toContain("CLT-CRED-002");
	});

	it("detects exported secret token", () => {
		const ids = matchCommand(engine, "export SECRET_TOKEN=mytoken123");
		expect(ids).toContain("CLT-CRED-002");
	});

	it("detects .env file write", () => {
		const ids = matchCommand(engine, 'echo "DB_PASS=secret" >> .env');
		expect(ids).toContain("CLT-CRED-003");
	});

	it("detects .env.local file write", () => {
		const ids = matchCommand(engine, 'echo "KEY=val" > .env.local');
		expect(ids).toContain("CLT-CRED-003");
	});

	it("detects cat .env", () => {
		const ids = matchCommand(engine, "cat .env");
		expect(ids).toContain("CLT-CRED-004");
	});

	it("detects cat AWS credentials", () => {
		const ids = matchCommand(engine, "cat ~/.aws/credentials");
		expect(ids).toContain("CLT-CRED-004");
	});

	it("detects cat SSH key", () => {
		const ids = matchCommand(engine, "cat ~/.ssh/id_rsa");
		expect(ids).toContain("CLT-CRED-004");
	});

	it("detects plaintext password", () => {
		const ids = matchCommand(engine, 'PASSWORD="supersecret123"');
		expect(ids).toContain("CLT-CRED-005");
	});

	it("detects GitHub PAT (long form)", () => {
		const ids = matchCommand(
			engine,
			"git clone https://github_pat_1234567890abcdefghijkl@github.com/user/repo",
		);
		expect(ids).toContain("CLT-CRED-006");
	});

	it("detects SendGrid key", () => {
		const ids = matchCommand(
			engine,
			"curl -H 'Authorization: Bearer SG.abcdefghijklmnopqrstuvw.xyzABCDEFGHIJKLMNOPQRSTU' https://api.sendgrid.com/v3/mail/send",
		);
		expect(ids).toContain("CLT-CRED-006");
	});

	it("detects Stripe live key", () => {
		const ids = matchCommand(
			engine,
			"curl https://api.stripe.com/v1/charges -u sk_live_1234567890abcdefghijklmn:",
		);
		expect(ids).toContain("CLT-CRED-006");
	});

	// --- sk-proj- OpenAI key variants (CRED-001 fix) ---

	it("detects sk-proj- prefixed OpenAI key", () => {
		const ids = matchCommand(
			engine,
			'curl -H "Authorization: Bearer sk-proj-RwszCFrRo3TS8axwaqQOS-HBMqDC5PM1huNW_s18se" https://api.openai.com/v1/chat',
		);
		expect(ids).toContain("CLT-CRED-001");
	});

	it("detects sk- key with hyphens and underscores", () => {
		const ids = matchCommand(
			engine,
			'curl -H "Authorization: Bearer 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" https://api.openai.com',
		);
		expect(ids).toContain("CLT-CRED-001");
	});

	// --- Negative cases ---

	it("does not match export PATH", () => {
		const ids = matchCommand(engine, "export PATH=/usr/local/bin:$PATH");
		expect(ids.filter((id) => id.startsWith("CLT-CRED"))).toEqual([]);
	});

	it("does not match versioned pip install", () => {
		const ids = matchCommand(engine, "pip install requests==2.31.0");
		expect(ids.filter((id) => id.startsWith("CLT-CRED"))).toEqual([]);
	});

	it("does not match echo hello", () => {
		const ids = matchCommand(engine, "echo hello world");
		expect(ids.filter((id) => id.startsWith("CLT-CRED"))).toEqual([]);
	});
});

import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("persistence threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- Positive cases ---

	it("detects bashrc append", () => {
		const ids = matchCommand(engine, 'echo "export PATH=/evil" >> ~/.bashrc');
		expect(ids).toContain("CLT-PERSIST-007");
	});

	it("detects zshrc redirect", () => {
		const ids = matchCommand(engine, "echo alias evil=hack >> ~/.zshrc");
		expect(ids).toContain("CLT-PERSIST-007");
	});

	it("detects crontab -e", () => {
		const ids = matchCommand(engine, "crontab -e");
		expect(ids).toContain("CLT-PERSIST-002");
	});

	it("does NOT detect crontab -l (harmless listing)", () => {
		const ids = matchCommand(engine, "crontab -l");
		expect(ids).not.toContain("CLT-PERSIST-002");
	});

	it("detects cron.daily write", () => {
		const ids = matchCommand(engine, "cp backdoor.sh /etc/cron.daily/cleanup");
		expect(ids).toContain("CLT-PERSIST-003");
	});

	it("detects LaunchAgents plist copy", () => {
		const ids = matchCommand(engine, "cp evil.plist ~/Library/LaunchAgents/com.evil.agent.plist");
		expect(ids).toContain("CLT-PERSIST-004");
	});

	it("detects LaunchDaemons plist copy", () => {
		const ids = matchCommand(engine, "cp evil.plist /Library/LaunchDaemons/com.evil.daemon.plist");
		expect(ids).toContain("CLT-PERSIST-004");
	});

	it("detects systemctl enable", () => {
		const ids = matchCommand(engine, "systemctl enable evil-service");
		expect(ids).toContain("CLT-PERSIST-005");
	});

	it("detects systemd unit write", () => {
		const ids = matchCommand(engine, "cp evil.service /etc/systemd/system/evil.service");
		expect(ids).toContain("CLT-PERSIST-005");
	});

	it("detects SSH authorized_keys append", () => {
		const ids = matchCommand(engine, "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys");
		expect(ids).toContain("CLT-PERSIST-006");
	});

	it("detects profile write", () => {
		const ids = matchCommand(engine, "echo 'export FOO=bar' >> ~/.profile");
		expect(ids).toContain("CLT-PERSIST-007");
	});

	// --- Negative cases ---

	it("does not match source bashrc", () => {
		const ids = matchCommand(engine, "source ~/.bashrc");
		expect(ids.filter((id) => id.startsWith("CLT-PERSIST"))).toEqual([]);
	});

	it("does not match cat bashrc", () => {
		const ids = matchCommand(engine, "cat ~/.bashrc");
		expect(ids.filter((id) => id.startsWith("CLT-PERSIST"))).toEqual([]);
	});

	it("does not match echo hello", () => {
		const ids = matchCommand(engine, "echo hello world");
		expect(ids.filter((id) => id.startsWith("CLT-PERSIST"))).toEqual([]);
	});
});

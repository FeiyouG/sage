import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchFilePath = createMatcher("file_path");

describe("file path threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- System authentication files (CLT-FILE-001) ---

	it("detects /etc/passwd", () => {
		expect(matchFilePath(engine, "/etc/passwd")).toContain("CLT-FILE-001");
	});

	it("detects /etc/shadow", () => {
		expect(matchFilePath(engine, "/etc/shadow")).toContain("CLT-FILE-001");
	});

	it("detects /etc/sudoers", () => {
		expect(matchFilePath(engine, "/etc/sudoers")).toContain("CLT-FILE-001");
	});

	// --- SSH authorized keys (CLT-FILE-002) ---

	it("detects .ssh/authorized_keys (absolute)", () => {
		expect(matchFilePath(engine, "/home/user/.ssh/authorized_keys")).toContain("CLT-FILE-002");
	});

	it("detects .ssh/authorized_keys (tilde)", () => {
		expect(matchFilePath(engine, "~/.ssh/authorized_keys")).toContain("CLT-FILE-002");
	});

	// --- SSH keys and config (CLT-FILE-003) ---

	it("detects .ssh/id_rsa", () => {
		expect(matchFilePath(engine, "/home/user/.ssh/id_rsa")).toContain("CLT-FILE-003");
	});

	it("detects .ssh/id_ed25519", () => {
		expect(matchFilePath(engine, "/home/user/.ssh/id_ed25519")).toContain("CLT-FILE-003");
	});

	it("detects .ssh/config", () => {
		expect(matchFilePath(engine, "/home/user/.ssh/config")).toContain("CLT-FILE-003");
	});

	// --- Shell RC files (CLT-FILE-004) ---

	it("detects .bashrc", () => {
		expect(matchFilePath(engine, "/home/user/.bashrc")).toContain("CLT-FILE-004");
	});

	it("detects .zshrc", () => {
		expect(matchFilePath(engine, "/home/user/.zshrc")).toContain("CLT-FILE-004");
	});

	it("detects .profile", () => {
		expect(matchFilePath(engine, "/home/user/.profile")).toContain("CLT-FILE-004");
	});

	it("detects .bash_profile", () => {
		expect(matchFilePath(engine, "/home/user/.bash_profile")).toContain("CLT-FILE-004");
	});

	it("detects .zprofile", () => {
		expect(matchFilePath(engine, "/home/user/.zprofile")).toContain("CLT-FILE-004");
	});

	it("detects .zshenv", () => {
		expect(matchFilePath(engine, "/home/user/.zshenv")).toContain("CLT-FILE-004");
	});

	// --- macOS LaunchAgents/Daemons (CLT-FILE-005) ---

	it("detects LaunchAgents plist", () => {
		expect(matchFilePath(engine, "~/Library/LaunchAgents/com.evil.agent.plist")).toContain(
			"CLT-FILE-005",
		);
	});

	it("detects LaunchDaemons plist", () => {
		expect(matchFilePath(engine, "/Library/LaunchDaemons/com.evil.daemon.plist")).toContain(
			"CLT-FILE-005",
		);
	});

	// --- Cron (CLT-FILE-006) ---

	it("detects cron.daily", () => {
		expect(matchFilePath(engine, "/etc/cron.daily/cleanup")).toContain("CLT-FILE-006");
	});

	it("detects cron.d", () => {
		expect(matchFilePath(engine, "/etc/cron.d/malicious")).toContain("CLT-FILE-006");
	});

	it("detects /var/spool/cron", () => {
		expect(matchFilePath(engine, "/var/spool/cron/root")).toContain("CLT-FILE-006");
	});

	// --- Systemd (CLT-FILE-007) ---

	it("detects systemd unit file", () => {
		expect(matchFilePath(engine, "/etc/systemd/system/evil.service")).toContain("CLT-FILE-007");
	});

	// --- Credential files (CLT-FILE-008) ---

	it("detects .env file", () => {
		expect(matchFilePath(engine, "/app/.env")).toContain("CLT-FILE-008");
	});

	it("detects .env.local file", () => {
		expect(matchFilePath(engine, "/app/.env.local")).toContain("CLT-FILE-008");
	});

	it("detects .env.production file", () => {
		expect(matchFilePath(engine, "/app/.env.production")).toContain("CLT-FILE-008");
	});

	it("detects .aws/credentials", () => {
		expect(matchFilePath(engine, "/home/user/.aws/credentials")).toContain("CLT-FILE-008");
	});

	it("detects .netrc", () => {
		expect(matchFilePath(engine, "/home/user/.netrc")).toContain("CLT-FILE-008");
	});

	it("detects .pgpass", () => {
		expect(matchFilePath(engine, "/home/user/.pgpass")).toContain("CLT-FILE-008");
	});

	// --- Git hooks (CLT-FILE-009) ---

	it("detects git hook", () => {
		expect(matchFilePath(engine, "/repo/.git/hooks/pre-commit")).toContain("CLT-FILE-009");
	});

	// --- Negative cases ---

	it("does not match normal tmp file", () => {
		const ids = matchFilePath(engine, "/tmp/notes.txt");
		expect(ids.filter((id) => id.startsWith("CLT-FILE"))).toEqual([]);
	});

	it("does not match normal source file", () => {
		const ids = matchFilePath(engine, "src/app.py");
		expect(ids.filter((id) => id.startsWith("CLT-FILE"))).toEqual([]);
	});

	it("does not match normal config file", () => {
		const ids = matchFilePath(engine, "/app/config/settings.json");
		expect(ids.filter((id) => id.startsWith("CLT-FILE"))).toEqual([]);
	});

	it("does not match README", () => {
		const ids = matchFilePath(engine, "/project/README.md");
		expect(ids.filter((id) => id.startsWith("CLT-FILE"))).toEqual([]);
	});

	it("does not match package.json", () => {
		const ids = matchFilePath(engine, "/project/package.json");
		expect(ids.filter((id) => id.startsWith("CLT-FILE"))).toEqual([]);
	});
});

/**
 * Audit logger for Sage verdicts.
 * Appends JSON Lines entries to ~/.sage/audit.jsonl for forensics and debugging.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import type { LoggingConfig, Verdict } from "./types.js";

const MAX_SUMMARY_LEN = 200;

function toolInputSummary(toolName: string, toolInput: Record<string, unknown>): string {
	if (toolName === "Bash") {
		return String(toolInput.command ?? "").slice(0, MAX_SUMMARY_LEN);
	}
	if (toolName === "WebFetch") {
		return String(toolInput.url ?? "").slice(0, MAX_SUMMARY_LEN);
	}
	if (toolName === "Write" || toolName === "Edit") {
		return String(toolInput.file_path ?? "").slice(0, MAX_SUMMARY_LEN);
	}
	return JSON.stringify(toolInput).slice(0, MAX_SUMMARY_LEN);
}

export async function logVerdict(
	config: LoggingConfig,
	sessionId: string,
	toolName: string,
	toolInput: Record<string, unknown>,
	verdict: Verdict,
	userOverride = false,
): Promise<void> {
	if (!config.enabled) return;

	// Skip clean verdicts unless log_clean is on or this is a user override
	if (verdict.decision === "allow" && !config.log_clean && !userOverride) return;

	const entry = {
		type: "runtime_verdict",
		timestamp: new Date().toISOString(),
		session_id: sessionId,
		tool_name: toolName,
		tool_input_summary: toolInputSummary(toolName, toolInput),
		artifacts: verdict.artifacts,
		verdict: verdict.decision,
		severity: verdict.severity,
		reasons: verdict.reasons,
		source: verdict.source,
		user_override: userOverride,
	};

	const path = resolvePath(config.path);
	try {
		await mkdir(dirname(path), { recursive: true });
		await appendFile(path, `${JSON.stringify(entry)}\n`);
	} catch {
		// Fail-open: logging errors swallowed
	}
}

export async function logPluginScan(
	config: LoggingConfig,
	pluginKey: string,
	pluginVersion: string,
	findings: Record<string, unknown>[],
): Promise<void> {
	if (!config.enabled) return;

	const entry = {
		type: "plugin_scan",
		timestamp: new Date().toISOString(),
		plugin_key: pluginKey,
		plugin_version: pluginVersion,
		findings_count: findings.length,
		findings,
	};

	const path = resolvePath(config.path);
	try {
		await mkdir(dirname(path), { recursive: true });
		await appendFile(path, `${JSON.stringify(entry)}\n`);
	} catch {
		// Fail-open
	}
}

export async function getRecentEntries(config: LoggingConfig, limit = 100): Promise<unknown[]> {
	const path = resolvePath(config.path);

	try {
		const content = await getFileContent(path);
		const lines = content.trim().split("\n");
		const recent = lines.slice(-limit);
		const entries: unknown[] = [];
		for (const line of recent) {
			try {
				entries.push(JSON.parse(line));
			} catch {}
		}
		return entries;
	} catch {
		return [];
	}
}

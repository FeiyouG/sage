/**
 * Approval tracker for Sage PostToolUse → MCP allowlist flow.
 *
 * Two files:
 * - pending-approvals.json: Written by PreToolUse on `ask`, keyed by tool_use_id.
 * - consumed-approvals.json: Written by PostToolUse after user approves, keyed by artifact hash.
 *
 * Pending entries are pruned after 1 hour. Consumed entries expire after 10 minutes.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { getFileContent, type Logger, nullLogger, resolvePath } from "@sage/core";

const PENDING_PATH = "~/.sage/pending-approvals.json";
const CONSUMED_PATH = "~/.sage/consumed-approvals.json";

const PENDING_STALE_MS = 60 * 60 * 1000; // 1 hour
const CONSUMED_TTL_MS = 10 * 60 * 1000; // 10 minutes

export interface PendingApproval {
	threatId: string;
	threatTitle: string;
	artifact: string;
	artifactType: string;
	createdAt: string;
}

export interface ConsumedApproval {
	threatId: string;
	threatTitle: string;
	artifact: string;
	artifactType: string;
	approvedAt: string;
	expiresAt: string;
}

type PendingStore = Record<string, PendingApproval>;
type ConsumedStore = Record<string, ConsumedApproval>;

async function loadJson<T>(path: string): Promise<T | null> {
	try {
		const raw = await getFileContent(resolvePath(path));
		return JSON.parse(raw) as T;
	} catch {
		return null;
	}
}

async function saveJson(path: string, data: unknown): Promise<void> {
	const resolved = resolvePath(path);
	await mkdir(dirname(resolved), { recursive: true });
	await writeFile(resolved, `${JSON.stringify(data, null, 2)}\n`);
}

function pruneStalePending(store: PendingStore): PendingStore {
	const now = Date.now();
	const result: PendingStore = {};
	for (const [key, entry] of Object.entries(store)) {
		if (now - new Date(entry.createdAt).getTime() < PENDING_STALE_MS) {
			result[key] = entry;
		}
	}
	return result;
}

/** Stable key for consumed-approvals lookup. */
function consumedKey(artifactType: string, artifact: string): string {
	return `${artifactType}:${artifact}`;
}

export async function addPendingApproval(
	toolUseId: string,
	approval: Omit<PendingApproval, "createdAt">,
	logger: Logger = nullLogger,
): Promise<void> {
	try {
		let store = (await loadJson<PendingStore>(PENDING_PATH)) ?? {};
		store = pruneStalePending(store);
		store[toolUseId] = { ...approval, createdAt: new Date().toISOString() };
		await saveJson(PENDING_PATH, store);
	} catch (e) {
		logger.warn("Failed to write pending approval", { error: String(e) });
	}
}

export async function consumePendingApproval(
	toolUseId: string,
	logger: Logger = nullLogger,
): Promise<PendingApproval | null> {
	try {
		let store = (await loadJson<PendingStore>(PENDING_PATH)) ?? {};
		store = pruneStalePending(store);
		const entry = store[toolUseId];
		if (!entry) return null;

		// Remove from pending
		delete store[toolUseId];
		await saveJson(PENDING_PATH, store);

		// Write to consumed with TTL
		const consumed = (await loadJson<ConsumedStore>(CONSUMED_PATH)) ?? {};
		const now = new Date();
		const key = consumedKey(entry.artifactType, entry.artifact);
		consumed[key] = {
			threatId: entry.threatId,
			threatTitle: entry.threatTitle,
			artifact: entry.artifact,
			artifactType: entry.artifactType,
			approvedAt: now.toISOString(),
			expiresAt: new Date(now.getTime() + CONSUMED_TTL_MS).toISOString(),
		};
		await saveJson(CONSUMED_PATH, consumed);

		return entry;
	} catch (e) {
		logger.warn("Failed to consume pending approval", { error: String(e) });
		return null;
	}
}

export async function findConsumedApproval(
	artifactType: string,
	artifact: string,
	logger: Logger = nullLogger,
): Promise<ConsumedApproval | null> {
	try {
		const store = (await loadJson<ConsumedStore>(CONSUMED_PATH)) ?? {};
		const key = consumedKey(artifactType, artifact);
		const entry = store[key];
		if (!entry) return null;

		if (new Date(entry.expiresAt).getTime() < Date.now()) {
			return null;
		}
		return entry;
	} catch (e) {
		logger.warn("Failed to read consumed approvals", { error: String(e) });
		return null;
	}
}

export async function removeConsumedApproval(
	artifactType: string,
	artifact: string,
	logger: Logger = nullLogger,
): Promise<void> {
	try {
		const store = (await loadJson<ConsumedStore>(CONSUMED_PATH)) ?? {};
		const key = consumedKey(artifactType, artifact);
		delete store[key];
		await saveJson(CONSUMED_PATH, store);
	} catch (e) {
		logger.warn("Failed to remove consumed approval", { error: String(e) });
	}
}

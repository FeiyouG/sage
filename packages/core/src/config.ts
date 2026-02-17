/**
 * Configuration loader for Sage.
 * Loads settings from ~/.sage/config.json with full defaults fallback.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { getFileContent } from "./file-utils.js";
import type { Config, Logger } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

const DEFAULT_CONFIG_PATH = join(homedir(), ".sage", "config.json");

/** Expand ~ to the user's home directory. */
export function resolvePath(pathStr: string): string {
	if (pathStr.startsWith("~/") || pathStr === "~") {
		return join(homedir(), pathStr.slice(1));
	}
	return pathStr;
}

export async function loadConfig(
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<Config> {
	const path = configPath ?? DEFAULT_CONFIG_PATH;

	let raw: string;
	try {
		raw = await getFileContent(path);
	} catch {
		// Missing file → full defaults (fail-open)
		return ConfigSchema.parse({});
	}

	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to parse config from ${path}`, { error: String(e) });
		return ConfigSchema.parse({});
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Config file ${path} does not contain a JSON object`);
		return ConfigSchema.parse({});
	}

	try {
		return ConfigSchema.parse(data);
	} catch (e) {
		logger.warn(`Config validation failed, using defaults`, { error: String(e) });
		return ConfigSchema.parse({});
	}
}

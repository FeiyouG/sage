#!/usr/bin/env node

/**
 * Sage MCP server for Claude Code.
 * Provides two tools:
 * - sage_allowlist_add: Add a URL or command to the allowlist (requires prior user approval)
 * - sage_allowlist_remove: Remove a URL or command from the allowlist (ungated)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
	addCommand,
	addUrl,
	hashCommand,
	type Logger,
	loadAllowlist,
	loadConfig,
	normalizeUrl,
	removeCommand,
	removeUrl,
	saveAllowlist,
} from "@sage/core";
import pino from "pino";
import { z } from "zod";
import { findConsumedApproval, removeConsumedApproval } from "./approval-tracker.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

const server = new McpServer({
	name: "sage",
	version: __SAGE_VERSION__,
});

declare const __SAGE_VERSION__: string;

server.registerTool(
	"sage_allowlist_add",
	{
		title: "Sage: Add to Allowlist",
		description:
			"Permanently allow a specific URL or command that was previously flagged by Sage. " +
			"Requires the user to have recently approved this exact artifact through Sage's security dialog.",
		inputSchema: z.object({
			type: z.enum(["url", "command"]).describe("Type of artifact to allowlist"),
			value: z.string().describe("The exact URL or command to allowlist"),
			reason: z.string().optional().describe("Why this is being allowlisted"),
		}),
	},
	async ({ type, value, reason }) => {
		try {
			const consumed = await findConsumedApproval(type, value, logger);
			if (!consumed) {
				return {
					content: [
						{
							type: "text" as const,
							text: "Cannot add to allowlist: no recent user approval found for this artifact. The user must first encounter and approve this action through Sage's security dialog, then you can permanently allowlist it.",
						},
					],
					isError: true,
				};
			}

			const config = await loadConfig(undefined, logger);
			const allowlist = await loadAllowlist(config.allowlist, logger);
			const entryReason = reason ?? `Approved by user (threat: ${consumed.threatId})`;

			if (type === "url") {
				addUrl(allowlist, value, entryReason, "ask");
			} else {
				addCommand(allowlist, value, entryReason, "ask");
			}

			await saveAllowlist(allowlist, config.allowlist, logger);
			await removeConsumedApproval(type, value, logger);

			const display =
				type === "url" ? normalizeUrl(value) : `command hash ${hashCommand(value).slice(0, 12)}...`;
			return {
				content: [
					{
						type: "text" as const,
						text: `Added ${type} to Sage allowlist: ${display}. This ${type} will no longer trigger security alerts.`,
					},
				],
			};
		} catch (e) {
			return {
				content: [{ type: "text" as const, text: `Failed to add to allowlist: ${e}` }],
				isError: true,
			};
		}
	},
);

server.registerTool(
	"sage_allowlist_remove",
	{
		title: "Sage: Remove from Allowlist",
		description:
			"Remove a URL or command from the Sage allowlist, restoring security checks for it.",
		inputSchema: z.object({
			type: z.enum(["url", "command"]).describe("Type of artifact to remove"),
			value: z
				.string()
				.describe("The URL to remove, or for commands: the command text or its SHA-256 hash"),
		}),
	},
	async ({ type, value }) => {
		try {
			const config = await loadConfig(undefined, logger);
			const allowlist = await loadAllowlist(config.allowlist, logger);

			let removed: boolean;
			if (type === "url") {
				removed = removeUrl(allowlist, value);
			} else {
				// Try as hash first, then as command text
				removed = removeCommand(allowlist, value);
				if (!removed) {
					removed = removeCommand(allowlist, hashCommand(value));
				}
			}

			if (!removed) {
				return {
					content: [
						{
							type: "text" as const,
							text: `${type === "url" ? "URL" : "Command"} not found in the allowlist.`,
						},
					],
				};
			}

			await saveAllowlist(allowlist, config.allowlist, logger);
			return {
				content: [
					{
						type: "text" as const,
						text: `Removed ${type} from Sage allowlist. Security checks will apply to this ${type} again.`,
					},
				],
			};
		} catch (e) {
			return {
				content: [{ type: "text" as const, text: `Failed to remove from allowlist: ${e}` }],
				isError: true,
			};
		}
	},
);

async function main(): Promise<void> {
	const transport = new StdioServerTransport();
	await server.connect(transport);
}

main().catch((e) => {
	logger.error("MCP server failed", { error: String(e) });
	process.exit(1);
});

import { beforeAll, describe, expect, it } from "vitest";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const matchCommand = createMatcher("command");

describe("command threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- CLT-CMD-022: Loop-based indirect execution ---

	it("detects while loop executing bash", () => {
		const ids = matchCommand(engine, 'while read line; do bash -c "$line"; done');
		expect(ids).toContain("CLT-CMD-022");
	});

	it("detects for loop executing curl", () => {
		const ids = matchCommand(engine, "for url in $URLS; do curl $url | sh; done");
		expect(ids).toContain("CLT-CMD-022");
	});

	it("detects for loop executing wget", () => {
		const ids = matchCommand(engine, "for f in list.txt; do wget -q $f; done");
		expect(ids).toContain("CLT-CMD-022");
	});

	it("does not match for loop with safe commands", () => {
		const ids = matchCommand(engine, "for f in *.txt; do cat $f; done");
		expect(ids).not.toContain("CLT-CMD-022");
	});

	it("does not match for loop with echo", () => {
		const ids = matchCommand(engine, 'for i in 1 2 3; do echo "$i"; done');
		expect(ids).not.toContain("CLT-CMD-022");
	});
});

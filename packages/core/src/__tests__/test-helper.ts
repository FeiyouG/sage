import { resolve } from "node:path";
import { HeuristicsEngine } from "../heuristics.js";
import { loadThreats } from "../threat-loader.js";
import type { Artifact } from "../types.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");

export async function loadEngine(): Promise<HeuristicsEngine> {
	const threats = await loadThreats(THREATS_DIR);
	return new HeuristicsEngine(threats);
}

export function createMatcher(
	artifactType: "command" | "content" | "file_path",
): (engine: HeuristicsEngine, value: string) => string[] {
	return (engine: HeuristicsEngine, value: string): string[] => {
		const artifacts: Artifact[] = [{ type: artifactType, value }];
		return engine.match(artifacts).map((m) => m.threat.id);
	};
}

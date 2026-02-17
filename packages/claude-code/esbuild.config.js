import * as esbuild from "esbuild";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("../core/package.json", "utf-8"));

const shared = {
	bundle: true,
	platform: "node",
	target: "node22",
	format: "cjs",
	external: [],
	sourcemap: true,
	define: { __SAGE_VERSION__: JSON.stringify(pkg.version) },
};

await esbuild.build({
	...shared,
	entryPoints: ["src/pre-tool-use.ts"],
	outfile: "dist/pre-tool-use.cjs",
});

await esbuild.build({
	...shared,
	entryPoints: ["src/session-start.ts"],
	outfile: "dist/session-start.cjs",
});

console.log("Build complete.");

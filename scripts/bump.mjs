#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const SEMVER_RE = /^\d+\.\d+\.\d+$/;

const ROOT = resolve(import.meta.dirname, "..");

const FILES = [
  {
    path: resolve(ROOT, "packages/core/package.json"),
    update(json, version) {
      json.version = version;
    },
  },
  {
    path: resolve(ROOT, "packages/claude-code/package.json"),
    update(json, version) {
      json.version = version;
    },
  },
  {
    path: resolve(ROOT, "packages/extension/package.json"),
    update(json, version) {
      json.version = version;
    },
  },
  {
    path: resolve(ROOT, "packages/openclaw/package.json"),
    update(json, version) {
      json.version = version;
    },
  },
  {
    path: resolve(ROOT, "packages/openclaw/openclaw.plugin.json"),
    update(json, version) {
      json.version = version;
    },
  },
  {
    path: resolve(ROOT, ".claude-plugin/plugin.json"),
    update(json, version) {
      json.version = version;
    },
  },
  {
    path: resolve(ROOT, ".claude-plugin/marketplace.json"),
    update(json, version) {
      json.version = version;
      for (const plugin of json.plugins ?? []) {
        plugin.version = version;
      }
    },
  },
];

const version = process.argv[2];

if (!version) {
  console.error("Usage: node scripts/bump.mjs <version>");
  console.error("Example: node scripts/bump.mjs 0.4.0");
  process.exit(1);
}

if (!SEMVER_RE.test(version)) {
  console.error(`Invalid semver: "${version}" (expected X.Y.Z)`);
  process.exit(1);
}

for (const file of FILES) {
  let raw;
  try {
    raw = readFileSync(file.path, "utf-8");
  } catch (err) {
    console.error(`Missing file: ${file.path}`);
    process.exit(1);
  }

  const json = JSON.parse(raw);
  const prev = json.version;
  file.update(json, version);
  writeFileSync(file.path, `${JSON.stringify(json, null, 2)}\n`);
  console.log(`${file.path.replace(ROOT + "/", "")}  ${prev} -> ${version}`);
}

console.log(`\nAll files updated to ${version}`);

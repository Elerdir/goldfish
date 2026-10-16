#!/usr/bin/env node
// Sets the Goldfish version everywhere it has to match (release checks tag == version):
//   Cargo.toml [workspace.package], crates/goldfish-tauri/tauri.conf.json,
//   src-frontend/package.json, Cargo.lock (workspace members goldfish-*).
// Usage: node scripts/bump-version.mjs 1.1.0
// Called by .forgejo/workflows/dispatch.yml (Linux runner); runs the same on Windows/macOS.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2];
// No pre-release: the MSI installer cannot represent X.Y.Z-rc.
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error("Usage: node scripts/bump-version.mjs <X.Y.Z>");
  process.exit(1);
}

const read = (p) => readFileSync(join(root, p), "utf8");
const write = (p, s) => writeFileSync(join(root, p), s, "utf8");

/** Replaces the FIRST match; a silent miss would ship a wrong version, so it throws. */
function replaceFirst(file, pattern, replacement) {
  const text = read(file);
  const match = text.match(pattern);
  if (!match) throw new Error(`${file}: pattern ${pattern} not found`);
  write(file, text.replace(pattern, replacement));
  return match[2];
}

const jsonVersion = /("version"\s*:\s*")([^"]+)(")/;
const cargoVersion = /(\[workspace\.package\][^[]*?\nversion\s*=\s*")([^"]+)(")/;

const changes = [
  ["Cargo.toml", replaceFirst("Cargo.toml", cargoVersion, `$1${version}$3`)],
  ["crates/goldfish-tauri/tauri.conf.json", replaceFirst("crates/goldfish-tauri/tauri.conf.json", jsonVersion, `$1${version}$3`)],
  ["src-frontend/package.json", replaceFirst("src-frontend/package.json", jsonVersion, `$1${version}$3`)],
];

// Cargo.lock: without this `cargo build --locked` fails with "lock file needs to be updated".
let touched = 0;
const lock = read("Cargo.lock").replace(
  /(\[\[package\]\]\nname = "goldfish-[a-z-]+"\nversion = ")([^"]+)(")/g,
  (_, a, _old, c) => {
    touched++;
    return `${a}${version}${c}`;
  },
);
if (touched === 0) throw new Error("Cargo.lock: no workspace member (goldfish-*) found");
write("Cargo.lock", lock);

for (const [file, old] of changes) console.log(`${file}: ${old} -> ${version}`);
console.log(`Cargo.lock: ${touched} goldfish-* packages`);

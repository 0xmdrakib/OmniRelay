import { readFile, readdir, stat } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist/", import.meta.url));
const files = [];

async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else files.push(path);
  }
}

await collect(root);
if (files.length === 0) throw new Error("Website build is empty");

const forbiddenExtensions = new Set([".kt", ".kts", ".java", ".aidl", ".ts", ".tsx", ".map"]);
const forbiddenContent = [
  "package com.example.omnirelay",
  "class OmniRelayService",
  "FIREBASE_SERVICE_ACCOUNT_JSON",
  "LIVEKIT_API_SECRET",
  "POSTGRES_PASSWORD"
];

for (const path of files) {
  const name = relative(root, path).replaceAll("\\", "/");
  const details = await stat(path);
  if (forbiddenExtensions.has(extname(name))) throw new Error(`Forbidden source artifact: ${name}`);
  if (details.size > 300_000) throw new Error(`Public asset exceeds 300 KB budget: ${name}`);
  if (/\.(html|css|js|json|svg|txt|webmanifest)$/i.test(name)) {
    const contents = await readFile(path, "utf8");
    const forbidden = forbiddenContent.find((value) => contents.includes(value));
    if (forbidden) throw new Error(`Private application marker found in ${name}: ${forbidden}`);
  }
}

const index = await readFile(join(root, "index.html"), "utf8");
if (!index.includes("github.com/0xmdrakib/OmniRelay/releases/latest")) {
  throw new Error("Official GitHub Releases link is missing");
}
if (!index.includes("omnirelay-clay-relay.jpg")) throw new Error("Social preview artwork is missing");
if (index.includes("%PUBLIC_SITE_URL%")) throw new Error("Public site URL placeholder was not resolved");
if (!index.includes('rel="canonical" href="https://')) throw new Error("Canonical HTTPS URL is missing");

process.stdout.write(`Verified ${files.length} isolated public files.\n`);

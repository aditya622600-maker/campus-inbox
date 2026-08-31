import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";

const root = process.cwd();
const run = promisify(execFile);
const forbiddenFilePatterns = [
  /(^|\/)\.env$/i,
  /(^|\/)\.env\.(?!example$)/i,
  /(^|\/)\.tokens\.json$/i,
  /\.db(?:-shm|-wal)?$/i,
  /(^|\/)\.data\//i,
  /(^|\/)\.cache\//i,
];

const privateKeyMarker = ["-----BEGIN ", "PRIVATE KEY-----"].join("");
const checks = [
  { name: "Google OAuth client secret", pattern: /GOCSPX-[A-Za-z0-9_-]{20,}/g },
  { name: "Google OAuth access token", pattern: /ya29\.[A-Za-z0-9_-]{20,}/g },
  { name: "private key", pattern: new RegExp(privateKeyMarker, "g") },
  {
    name: "populated client_secret field",
    pattern: /["']?client_secret["']?\s*[:=]\s*["'](?!your_|replace_|example|<)[^"'\r\n]{16,}["']/gi,
  },
];

const { stdout } = await run(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: root, encoding: "utf8" },
);
const repositoryFiles = stdout.split("\0").filter(Boolean);

const findings = [];

for (const relativePath of repositoryFiles) {
  const normalizedPath = relativePath.replaceAll("\\", "/");
  if (forbiddenFilePatterns.some((pattern) => pattern.test(normalizedPath))) {
    findings.push(`${normalizedPath}: sensitive file must not be included`);
    continue;
  }

  const contents = await readFile(path.join(root, relativePath), "utf8").catch(() => null);
  if (contents === null) continue;

  for (const check of checks) {
    check.pattern.lastIndex = 0;
    if (check.pattern.test(contents)) {
      findings.push(`${normalizedPath}: possible ${check.name}`);
    }
  }
}

if (findings.length > 0) {
  console.error("Repository safety check failed:");
  for (const finding of findings) console.error(`- ${finding}`);
  process.exitCode = 1;
} else {
  console.log("Repository safety check passed: no credential patterns found.");
}
